#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include <capstone/capstone.h>

#include "ptools.h"

#include <string>
#include <map>

#include <iostream>
#include <vector>
#include <sstream>

using namespace std;

#define	PEEKSIZE	8

class instruction1 {
public:
	unsigned char bytes[16];
	int size;
	string opr, opnd;
};

static csh cshandle = 0;
static map<long long, instruction1> instructions;

void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}

int print_instruction(long long addr, instruction1 *in, const char *module) {
	int i;
	char bytes[128] = "";
	if(in == NULL) {
		fprintf(stderr, "0x%012llx<%s>:\t<cannot disassemble>\n", addr, module);
	} else {
		for(i = 0; i < in->size; i++) {  // print instruction base on instruction size
			snprintf(&bytes[i*3], 4, "%2.2x ", in->bytes[i]);
		}
		// fprintf(stderr, "0x%012llx<%s>: %-32s\t%-10s%s\n", addr, module, bytes, in->opr.c_str(), in->opnd.c_str());
		fprintf(stderr, "\t%06llx: %-32s\t%-10s%s\n", addr, bytes, in->opr.c_str(), in->opnd.c_str());

        // cout << "in->size: " << in->size << endl; -> bingo
        // printf("byte length +++++++ : %zu\n", strlen(bytes)); -> in->size * 5
	}

    return in->size;
}

int disassemble(pid_t proc, unsigned long long rip, const char *module) {
	int count;
	char buf[64] = { 0 };
	unsigned long long ptr = rip;
	cs_insn *insn;
	map<long long, instruction1>::iterator mi; // (memory address, instruction), from memory addr to instruction
    int instruction_size;

    // If ever recorded the instruction -> print & return
	if((mi = instructions.find(rip)) != instructions.end()) {
		instruction_size = print_instruction(rip, &mi->second, module);
		return instruction_size;
        // return print_instruction(rip, &mi->second, module);
	}

	for(ptr = rip; ptr < rip + sizeof(buf); ptr += PEEKSIZE) {  // peek 64 byte at a time
		long long peek;
		errno = 0;  // directly use errno
		peek = ptrace(PTRACE_PEEKTEXT, proc, ptr, NULL);
		if(errno != 0) break;
		memcpy(&buf[ptr-rip], &peek, PEEKSIZE);
	}

	if(ptr == rip)  {
		instruction_size = print_instruction(rip, NULL, module);
		return instruction_size;
	}

	if((count = cs_disasm(cshandle, (uint8_t*) buf, rip-ptr, rip, 0, &insn)) > 0) {
		int i;
		for(i = 0; i < count; i++) {
			instruction1 in;
			in.size = insn[i].size;
			in.opr  = insn[i].mnemonic;
			in.opnd = insn[i].op_str;
			memcpy(in.bytes, insn[i].bytes, insn[i].size);
			instructions[insn[i].address] = in;
            // cout << "in.size: " << in.size << endl;
            // cout << "in.opr: " << in.opr << endl;
            // cout << "in.opnd: " << in.opnd << endl;
		}
		cs_free(insn, count);
	}

	if((mi = instructions.find(rip)) != instructions.end()) {
		instruction_size =print_instruction(rip, &mi->second, module);
	} else {
		instruction_size =print_instruction(rip, NULL, module);
	}

	return instruction_size;
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

long unsigned get_code_end_address(const string& command) {
    // array<char, 128> buffer;
    char buffer[1024];
    string result;
    FILE* pipe = popen(command.c_str(), "r");
    int text_appear = 0;
    if (!pipe) {
        throw runtime_error("popen() failed!");
    }

    string text_address;
    int code_end_address = 0;
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        // cout << "buffer: " << buffer << endl;
        if(string(buffer).find(".text") != string::npos) {
            text_appear = 1;
            // cout << "address: " << split_string_by_space(string(buffer))[4] << endl;
            code_end_address = stoul(split_string_by_space(string(buffer))[4], nullptr, 16);

        } else if (text_appear == 1) {
            text_appear = 2;
            // cout << "len: " << split_string_by_space(string(buffer))[0] << endl;
            code_end_address += stoul(split_string_by_space(string(buffer))[0], nullptr, 16);
        }
    }
    pclose(pipe);

    return code_end_address - 1;  // start + len - 1 = end address
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
		map<range_t, map_entry_t> m;
		map<range_t, map_entry_t>::iterator mi;

		if(cs_open(CS_ARCH_X86, CS_MODE_64, &cshandle) != CS_ERR_OK)
			return -1;

		if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);

		if(load_maps(child, m) > 0) {
#if 0
			for(mi = m.begin(); mi != m.end(); mi++) {
				fprintf(stderr, "## %lx-%lx %04o %s\n",
					mi->second.range.begin, mi->second.range.end,
					mi->second.perm, mi->second.name.c_str());
			}
#endif
			fprintf(stderr, "## %zu map entries loaded.\n", m.size());
		}

        // see what in the m
        // ## 400000-401000 0005 hello64
        // ## 600000-601000 0007 hello64
        // ## 7ffe40e14000-7ffe40e35000 0007 [stack]
        // ## 7ffe40ebb000-7ffe40ebf000 0004 [vvar]
        // ## 7ffe40ebf000-7ffe40ec1000 0005 [vdso]
        // ## 7fffffffffffffff-7fffffffffffffff 0005 [vsyscall]
        // cout << "========== m ============" << endl;
        // for(mi = m.begin(); mi != m.end(); mi++) {
        //     fprintf(stderr, "## %lx-%lx %04o %s\n",
        //         mi->second.range.begin, mi->second.range.end,
        //         mi->second.perm, mi->second.name.c_str());
        // }
        // cout << "========== m ============" << endl;
        long unsigned code_end_address = get_code_end_address("readelf -S " + string(argv[1]));
        cout << "code_end_address: " << hex << code_end_address << dec << endl;  // success

        string user_input = "";
        bool entry_point = true;

		while (WIFSTOPPED(wait_status)) {
			struct user_regs_struct regs;
			counter++;
			if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                unsigned long instruction_address = regs.rip;

                if(entry_point) {
                    // program './hello' loaded. entry point 0x401000
                    // cout << "program '" + + "' loaded. entry point " +  << endl;
                    fprintf(stdout, "program '%s' loaded. entry point 0x%lx\n", argv[1], instruction_address);
                }

                // [DONE] - load five instructions ahead
                for(int i = 0; i < 5; i++) {
                    // fprintf(stderr, "0x%lx\n", instruction_address);
                    range_t r = { instruction_address, instruction_address };  // use current rip to get 
                    mi = m.find(r);  // find if the instruction ex: 0x4000b0 is in the map range
                    if(mi == m.end()) {
                        m.clear();
                        fprintf(stderr, "## %zu map entries re-loaded.\n", m.size());
                        mi = m.find(r);
                    }
                    instruction_address += disassemble(child, instruction_address, mi != m.end() ? mi->second.name.c_str() : "unknown");

                    // [DONE] - break next time's disass since next time's asm exceed the text section
                    if(instruction_address > code_end_address) {
                        cout << "** the address is out of the range of the text section." << endl;
                        break;
                    }
                }
			}

            // prompt
            // wait for user input for next step
            while(1) {  // wait until valid input
                cout << "(sdb) ";
                user_input = "";
                cin >> user_input;  // do not contain endline
                // cout << "user_input: " << user_input << endl;
                // cout << "user_input len: " << user_input.length() << endl;

                // [DONE] - support ins
                //  1. si
                //  2. cont
                if (user_input == "si") {
                    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) {
                        perror("ptrace");
                        cs_close(&cshandle);
                        return -2;
                    }
                    break;
                } else if (user_input == "cont") {
                    if(ptrace(PTRACE_CONT, child, 0, 0) < 0) {
                        perror("ptrace");
                        cs_close(&cshandle);
                        return -2;
                    }
                    break;
                } else {
                    cout << "Undefined command: \"" + user_input + "\"." << endl;
                }
            }

			if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		}

		// fprintf(stderr, "## %lld instructions(s) monitored\n", counter);
        cout << "** the target program terminated." << endl;
		cs_close(&cshandle);
	}
	return 0;
}

