#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/user.h>


void errquit(const char *msg) {
	perror(msg);
	exit(-1);
}


int try_magic(unsigned char *magic, int argc, char *argv[]) {
    // child is chals
	pid_t child;

	if((child = fork()) < 0) errquit("fork");
	
    if(child == 0) {
		if(ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) errquit("ptrace@child");
		execvp(argv[1], argv+1);
		errquit("execvp");
	} else {
        // counter count for CC();
		long long counter = 0LL;
		int wait_status;
		if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");
		ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_EXITKILL);
        
        // variables to store the information get from ptrace
        long ret;
        unsigned long long rip;
        unsigned long long rax;
        struct user_regs_struct regs;
        unsigned char *ptr = (unsigned char *) &ret;  // [TODO]

        unsigned long *magic_ptr = (unsigned long *)magic;  //[TODO] need magic_ptr to read content after magic size

        // get magic address from <main>
        // after 1st int3(CC)
        //      -> 2nd stop since child will stop for the 1st time after enter execvp
        // single step to stop after this instruction:
        //      lea    rax,[rip+0xcf849]        # d81c8 <magic>
        //      -> get the address store in rax out
        //      -> the address is the place to store magic
        //
        // process:
        //      enter child  = 1st stop 
        //      1st int3(CC) = 2nd stop
        //          memset magic    -> get magic address from rax
        //      2nd int3(CC) = 3rd stop
        //          other things    -> set magic by POKETEXT
        //      3rd int3(CC) = 4th stop
		while (WIFSTOPPED(wait_status)) {
			counter++;

            // after first int3(CC)
            if(counter == 2) {
                // run 3 single step to arrive "lea rax,[rip+0xcf849]"
                for(int i = 0; i < 3; i++) {
                    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0) < 0) errquit("ptrace@parent");
			        if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");  // wait for next stop
                }

                // after run over "lea rax,[rip+0xcf849]", get the rax out
                if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                    rax = regs.rax;
                }
            }

            // after 2nd int3(CC) = 3rd stop
            // change magic value here
            if (counter == 3) {
                // POKETEXT
                ret = ptrace(PTRACE_POKETEXT, child, rax, *(magic_ptr));
                if(ret != 0 ) errquit("POKETEXT");

                magic_ptr = (unsigned long *)magic;
                ret = ptrace(PTRACE_PEEKTEXT, child, rax+8, 0);  // for next PTRACE_POKETEXT ret use
                ret = ptrace(PTRACE_POKETEXT, child, rax+8, ((ret & 0xffffffffffff0000) | (*(magic_ptr + 1))));  // +1 is +8 byte(1 unit)
                if(ret != 0 ) errquit("POKETEXT");
            }

            if (counter == 6) {
                // after oracle_get_flag();, get rax asap
                if(ptrace(PTRACE_GETREGS, child, 0, &regs) == 0) {
                    rax = regs.rax;
                }
                if(rax == 0) {  // success
                    return 1;  // [TODO] let child terminate -> although original version the child will be killed after parent terminate due to the setting of PTRACE_O_EXITKILL
                }
            }

			if(ptrace(PTRACE_CONT, child, 0, 0) < 0) errquit("ptrace@parent");
			if(waitpid(child, &wait_status, 0) < 0) errquit("waitpid");  // wait for next stop
		}
	}

    return 0;
}


void get_magic (int index, unsigned char* magic) {
    int cnt = 0;
    while(index > 0) {
        if(index & 1)
            magic[cnt] = 0x31;
        
        index >>= 1;  // index shift right 1 
        cnt++;
    }
}


int main(int argc, char *argv[]) {

    if(argc < 2) {
		fprintf(stderr, "usage: %s program [args ...]\n", argv[0]);
		return -1;
	}

    for(int i = 0; i < 1024; i++) {  // 0 - 1023
        unsigned char magic[] = { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 };
        get_magic(i, magic);
        if(try_magic(magic, argc, argv) == 1) {
            // printf(" ===== try finish ===== ");
            break;
        }
    }

    return 0;
}

