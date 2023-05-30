#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <capstone/capstone.h>

#include <iostream>
#include <cstring>
#include <string>
#include <sstream>
#include <vector>
#include <map>

using namespace std;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

uint8_t* code;
long code_size;
map<unsigned long, unsigned char> break_point_archive;  // (address, 1 byte content)

void load_code(char *argv[]) {
    // load code
    FILE* code_file = fopen(argv[1], "rb");
    if (!code_file) {
        printf("Failed to open binary file.\n");
        return;
    }
    // get code_file size
    fseek(code_file, 0, SEEK_END);
    code_size = ftell(code_file);
    rewind(code_file);

    code = (uint8_t*)malloc(code_size);
    if (!code) {
        printf("Memory allocation failed.\n");
        fclose(code_file);
        return;
    }

    // memcpy();
    size_t bytes_read = fread(code, 1, code_size, code_file);
    if (bytes_read != static_cast<size_t>(code_size)) {
        printf("Failed to read code from file.\n");
        free(code);
        fclose(code_file);
        return;
    }

    fclose(code_file);
}


void load_next_five_instruction (unsigned long rip, unsigned long code_end_address) {
    // using capstone
    static csh cshandle = 0;

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
			return;

    size_t count;
    cs_insn *insn;
    // cout << "(rip - 0x400000): " << hex << (rip - 0x400000) << dec << endl;
    count = cs_disasm(cshandle, code + (rip - 0x400000), code_size, rip, 5, &insn);  // code, sizeof code, start disasm addr, hm ins, disasm result memory pointer
    // cout << "disasm count: " << count << endl;

    if (count > 0) {
		for (size_t i = 0; i < count; i++) {
            // disasm range check
            if(insn[i].address > code_end_address) {
                cout << "** the address is out of the range of the text section." << endl;
                break;
            }

            unsigned char in_bytes[16];
            memcpy(in_bytes, insn[i].bytes, insn[i].size);

            // parse in_bytes to output formula "bytes"
            // turn each byte to 2 hex value and append a " "
            char bytes[128] = "";
            for(int j = 0; j < insn[i].size; j++) {
                // 2nd para is max byte to use for formatting output including '\0' -> 00 '\0' -> 4 bytes
                snprintf(&bytes[j*3], 4, "%2.2x ", in_bytes[j]);
            }

            // cout << "insn[i].size: " << insn[i].size << endl;

            // %06lx: output hex value with 6 char len (not enough padding 0 infront)
            // %-32.*s: print insn[i].size amount of bytes
            // %-10s: formatting output insn[i].mnemonic with 10 char len
            // fprintf(stderr, "\t%06lx: %-32.*s\t%-10s%s\n", insn[i].address, insn[i].size * 3, bytes, insn[i].mnemonic, insn[i].op_str);
    		fprintf(stderr, "\t%06lx: %-32s\t%-10s%s\n", insn[i].address, bytes, insn[i].mnemonic, insn[i].op_str);
		}

		cs_free(insn, count);
	} else
		printf("ERROR: Failed to disassemble given code!\n");

	cs_close(&cshandle);
    return;
}

vector<string> split_string_by_space(const string& input) {
    istringstream iss(input);
    vector<string> tokens;
    tokens.clear();
    string token;

    while (getline(iss, token, ' ')) {
        if(token == "") continue;
        // cout << "token: " << token << endl;
        // cout << "token len: " << token.length() << endl;
        tokens.push_back(token);
    }

    return tokens;
}

void parse_elf(const string& command, unsigned long &code_start_address, unsigned long &code_end_address) {
    char buffer[1024];
    string result;
    FILE* pipe = popen(command.c_str(), "r");
    int text_appear = 0;
    if (!pipe) {
        throw runtime_error("popen() failed!");
    }

    string text_address;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        // cout << "buffer: " << buffer << endl;
        if(string(buffer).find(".text") != string::npos) {
            text_appear = 1;
            // cout << "address: " << split_string_by_space(string(buffer))[4] << endl;
            // code_end_address = stoul(split_string_by_space(string(buffer))[4], nullptr, 16);
            code_start_address = stoul(split_string_by_space(string(buffer))[4], nullptr, 16);

        } else if (text_appear == 1) {
            text_appear = 2;
            // cout << "len: " << split_string_by_space(string(buffer))[0] << endl;
            code_end_address = code_start_address + stoul(split_string_by_space(string(buffer))[0], nullptr, 16);
            // code_end_address += stoul(split_string_by_space(string(buffer))[0], nullptr, 16);
        }
    }
    pclose(pipe);
    code_end_address -= 1;
    return;
}

int main(int argc, char *argv[]) {
	pid_t child;
	if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}
	if((child = fork()) < 0) errquit("fork");
	if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv+1);
		errquit("execvp");
	} else {
		long long counter = 0LL;
		int wait_status;
		if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        // variable in while
        string user_input;
        struct user_regs_struct regs;
        unsigned long code_start_address, code_end_address;
        parse_elf("readelf -S " + string(argv[1]), code_start_address, code_end_address);
        load_code(argv);
		bool entry_point = true;

        while (WIFSTOPPED(wait_status)) {
			counter++;
            user_input = "";

            // [DONE] get register rip
            if(ptrace(PTRACE_GETREGS, child, 0, &regs) == -1) perror("PTRACE_GETREGS");

            if(entry_point) {
                fprintf(stdout, "program '%s' loaded. entry point 0x%llx\n", argv[1], regs.rip);
                entry_point = false;
            }

            // [DONE] load next five instruction based on rip
            load_next_five_instruction(regs.rip, code_end_address);

            // [TODO] deal with user input and decide next step action
            while(1) {  // wait until valid input
                cout << "(sdb) ";
                user_input = "";
                getline(cin, user_input);
                // cout << "user_input: " << user_input << endl;
                // cout << "user_input len: " << user_input.length() << endl;
                // cout << "user_input.substr(0, 6): " << user_input.substr(0, 6) << endl;


                // [DONE] - support ins
                //  1. si
                //  2. cont
                if (user_input == "si") {
                    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) {
                        perror("PTRACE_SINGLESTEP");
                        // cs_close(&cshandle);
                        return -2;
                    }
                    break;

                } else if (user_input == "cont") {
                    if(ptrace(PTRACE_CONT, child, 0, 0) < 0) {
                        perror("PTRACE_CONT");
                        // cs_close(&cshandle);
                        return -2;
                    }
                    break;
                
                } else if (user_input.substr(0, 6) == "break ") {
                    unsigned long break_point_address = stoul(split_string_by_space(user_input)[1], nullptr, 16);

                    // check the break point range
                    if(break_point_address < code_start_address || break_point_address > code_end_address) {
                        cout << " * break point address out of range." << endl;
                        continue;

                    }

                    // set break point
                    // -> overwrite the address's text to 0xcc and record the text
                    // 1. record text -> 2. overwrite the address's text to 0xcc -> 3. for future recover
                    // [remind] disasm cannot be 0xcc
                    unsigned long peek_word = ptrace(PTRACE_PEEKTEXT, child, break_point_address, 0);
                    // cout << "peek_word: " << hex << peek_word << dec << endl;
                    break_point_archive[break_point_address] = static_cast<unsigned char>(peek_word & 0xff);
                    // cout << "break_point_archive[break_point_address]: " << hex << static_cast<int>(break_point_archive[break_point_address]) << dec << endl;
                    // cout << "(peek_word & 0xffffffffffffff00) | 0xcc): " << hex << ((peek_word & 0xffffffffffffff00) | 0xcc) << dec << endl;
                    // ret = ptrace(PTRACE_POKETEXT, child, break_point_address, (restore_byte & 0xffffffffffffff00) | 0xcc);
                    if(ptrace(PTRACE_POKETEXT, child, break_point_address, (peek_word & 0xffffffffffffff00) | 0xcc) != 0 ) errquit("POKETEXT");

                    cout << "** set a breakpoint at 0x" << hex << break_point_address << dec << "." << endl;

                    // peek_word = ptrace(PTRACE_PEEKTEXT, child, break_point_address, 0);
                    // cout << "peek_word: " << hex << peek_word << dec << endl;

                    // change it pack -> ok
                    // if(ptrace(PTRACE_POKETEXT, child, break_point_address, (peek_word & 0xffffffffffffff00) | break_point_archive[break_point_address]) != 0 ) errquit("POKETEXT");
                    // peek_word = ptrace(PTRACE_PEEKTEXT, child, break_point_address, 0);
                    // cout << "peek_word: " << hex << peek_word << dec << endl;

                } else {
                    cout << " * Undefined command: \"" + user_input + "\"." << endl;
                }
            }
            
            if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");        
        }
		fprintf(stderr, "## %lld instruction(s) executed\n", counter);
	}
	return 0;
}

