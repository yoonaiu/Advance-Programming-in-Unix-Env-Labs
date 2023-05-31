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
#include <fstream>

using namespace std;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

unsigned long code_start_address, code_end_address, base_address;
uint8_t* code;
long code_size;
map<unsigned long, unsigned char> break_point_archive;  // (address, 1 byte content)
struct user_regs_struct regs;
pid_t child;

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

void load_base_address() {
    ifstream proc_self_maps("/proc/self/maps");
    if(proc_self_maps.is_open()) {
        string first_line;
        getline(proc_self_maps, first_line);
        base_address = stoul(first_line.substr(0, first_line.find("-")), nullptr, 16);
        proc_self_maps.close();
    } else {
        cerr << "Unable to open file: " << "/proc/self/maps" << '\n';
    }
    // cout << "base_address: " << hex << base_address << dec << endl;
    return;
}

void load_next_five_instruction() {
    // using capstone
    static csh cshandle = 0;

    if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
			return;

    size_t count;
    cs_insn *insn;
    count = cs_disasm(cshandle, code + (regs.rip - base_address), code_size, regs.rip, 5, &insn);  // code, sizeof code, start disasm addr, hm ins, disasm result memory pointer
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

void parse_elf(const string& command) {
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
            code_start_address = stoul(split_string_by_space(string(buffer))[4], nullptr, 16);

        } else if (text_appear == 1) {
            text_appear = 2;
            code_end_address = code_start_address + stoul(split_string_by_space(string(buffer))[0], nullptr, 16);
        }
    }
    pclose(pipe);
    code_end_address -= 1;
    return;
}


void wait_and_refresh_status(bool is_si) {
    int wait_status;
    if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");

    if (WIFSTOPPED(wait_status)) {
        
        if(is_si) {
            if(ptrace(PTRACE_GETREGS, child, 0, &regs) == -1) errquit("PTRACE_GETREGS");

            if(break_point_archive.find(regs.rip) != break_point_archive.end()) {  // next step is breakpoint
                // single_step silently to hit breakpoint here
                // after hitting breakpoint, next action (check if hit breakpoint / restore breakpoint remain the same)
                if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("PTRACE_SINGLESTEP");
                if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
            }
        }

        // load new regs state
        if(ptrace(PTRACE_GETREGS, child, 0, &regs) == -1) errquit("PTRACE_GETREGS");

        // check if hit the break point
        if(break_point_archive.find(regs.rip - 0x1) != break_point_archive.end()) {  // last stop is a breakpoint
            unsigned long break_point_address = regs.rip - 0x1;
            cout << "** hit a breakpoint 0x" << hex << break_point_address << hex << "." << endl;

            // recover the breakpoint
            unsigned long peek_word = ptrace(PTRACE_PEEKTEXT, child, break_point_address, 0);
            if(errno != 0) errquit("PTRACE_PEEKTEXT");
            // cout << "peek_word: " << hex << peek_word << dec << endl;

            if(ptrace(PTRACE_POKETEXT, child, break_point_address, (peek_word & 0xffffffffffffff00) | break_point_archive[break_point_address]) != 0 ) errquit("POKETEXT");

            peek_word = ptrace(PTRACE_PEEKTEXT, child, break_point_address, 0);
            if(errno != 0) errquit("PTRACE_PEEKTEXT");
            // cout << "peek_word: " << hex << peek_word << dec << endl;
            // -> seems ok

            // restore rip
            regs.rip = regs.rip-1;
            // regs.rdx = regs.rax; // why
            if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) errquit("PTRACE_SETREGS");
        }

    } else {  // program exit
        cout << "** the target program terminated." << endl;
    	exit(0);
    }

    return;
}


void set_break_point(const string &user_input) {
    unsigned long break_point_address = stoul(split_string_by_space(user_input)[1], nullptr, 16);
    // check the break point range
    if(break_point_address < code_start_address || break_point_address > code_end_address) {
        cout << " * break point address out of range." << endl;
        return;
    }

    // set break point
    // -> overwrite the address's text to 0xcc and record the text
    // 1. record text -> 2. overwrite the address's text to 0xcc -> 3. for future recover
    // [remind] disasm cannot be 0xcc
    unsigned long peek_word = ptrace(PTRACE_PEEKTEXT, child, break_point_address, 0);
    if(errno != 0) errquit("PTRACE_PEEKTEXT");

    break_point_archive[break_point_address] = static_cast<unsigned char>(peek_word & 0xff);
    if(ptrace(PTRACE_POKETEXT, child, break_point_address, (peek_word & 0xffffffffffffff00) | 0xcc) != 0 ) errquit("POKETEXT");

    cout << "** set a breakpoint at 0x" << hex << break_point_address << dec << "." << endl;
}


int main(int argc, char *argv[]) {
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
		int wait_status;
		if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

        // load base address
        load_base_address();

        // variable in while
        string user_input;

        // get code range address
        parse_elf("readelf -S " + string(argv[1]));
        
        // load binary code put into disasm
        load_code(argv);

        // entry point prompt
        if(ptrace(PTRACE_GETREGS, child, 0, &regs) == -1) errquit("PTRACE_GETREGS");
        fprintf(stdout, "program '%s' loaded. entry point 0x%llx\n", argv[1], regs.rip);
        load_next_five_instruction();

        // get user input and act coresspondingly
        while(true) {
            cout << "(sdb) ";
            user_input = "";
            getline(cin, user_input);

            if (user_input == "si") {
                if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("PTRACE_SINGLESTEP");
                wait_and_refresh_status(true);
                load_next_five_instruction();

            } else if (user_input == "cont") {
                if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("PTRACE_CONT");
                wait_and_refresh_status(false);
                load_next_five_instruction();

            } else if (user_input.substr(0, 6) == "break ") {
                set_break_point(user_input);

            } else {
                cout << " * Undefined command: \"" + user_input + "\"." << endl;
            }
        }
	}
	return 0;
}

