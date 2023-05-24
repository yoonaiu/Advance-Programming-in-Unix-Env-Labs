# Advance-Programming-in-Unix-env-labs
* Brief Introduction to each lab, to see more details, please visit \<lab-N\>_spec.jpg in each lab folder for more details.
* All the labs are designed by the professor ```Chun-Ying Huang``` at NYCU in Taiwan, and all the lab specs are excerpted from professor's lecture materials.

## lab08
> Topic - ptrace
>> Test the program on remote server ```nc up23.zoolab.org 10965``` by running ```python3 submit.py ./solver``` to submit the solver binary to the remote server. Once success, you will get flag from the server.
> 
>> Sample remote server code can be found in sample[1-3].c, can test locally by running sample{$1-3} binary as ```./sample[1-3].c ./solver``` This is the ```chals``` program
>
>> Compiling solver.c on x86_64 machine with command ```gcc -fPIE -static-pie solver.c -o solver``` to include the static binary so that it can run on the remote server. If want to test locally, simply use ```gcc solver.c -o solver``` to compile it.
* Refer to sample[1-3].c.c, remote server will use ```static char magic[11]``` first 10 bits to determine which step to take. After each step, will do ```oracle_update```, and this will effect the ```oracle_get_flag()``` running result.
* If you go into right path, then ```oracle_get_flag()``` will print a flag ```FLAG{@_simP1e_Ptr@ce_ex@mPl3_3d41a72c35c03e74c6fdd37c3225e73a}``` and return 0.
* Write a ptrace program to let the sample[1-3].c / remote program print the flag.
#### STEPS in ```solver.c```
  * Running 2nd argument's file name - the chals program (sample[1-3]) itself - as the child of the solver and use ptrace to control the process of the chals program
  * Make up combination of ```static char magic[11]``` 10 bits value, 1024 combinations in total, and aim to run 1024 times ./chals with different magic value to get the flag. Stop trying magic values once get the flag.
  * Utilize several ```CC()``` break points in chals - analyze the disasm result generate by objdump of chals programs ```objdump -d -intel sample1 > sample1.s```
    * After 1st int3(CC), get magic's data address in .data section(since it is static value) of the ELF by getting the rax(prtace - PTRACE_GETREGS) storing its address 3 single steps after 1st CC()
    * After 2nd int3(CC), change magic's value to the target try value after magic has been memset, change the value by using ptrace PTRACE_POKETEXT to write the address in chals's ELF's .data section which store the magic value,
    * After 6th int3(CC), the the return value of the ```oracle_get_flag()`` in rax to know if get the flag or not. If not, keep the trying process, if yes, stop trying and end the solver program.
> <img width="572" alt="image" src="https://github.com/yoonaiu/Advance-Programming-in-Unix-env-labs/assets/73454628/74ef6137-72da-4a81-bfe7-7320bf26b306">


  
