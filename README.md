# CTFProblems
CTF problems that I am making/ have made in the past.

The Makefiles for these problems are mostly going to be formatted to work with [ctf-tool](https://gitlab.com/cyberatuc/ctf-tool), a command line tool for hosting ctf problems via docker that I helped write. Rather than be dependant on that tool, you can also just launch the challenges on your own machine. To make the problems work individually, you can use the following code snippet:

```
cd "$CHALLENGE_NAME"
make
python3 ../challenge-listener.py "$(cat requires-server)" 1337
```

Dockerfiles may eventually be added so that hosting the challenges with a consistent version of libc/ environment is not such a hassol.



| Challenge name | Category | Difficulty | Status | Additional notes or requirements |
| ------ | ------ | ------ | ------ | ------ |
| EasyROP | pwn | easy/intermediate | READY | The version of libc can be provided if you are feeling nice, but it is also possible to look up the version based off of the leak |
| big-jump | reversing | easy | READY | the challenge is randomly generated every time make is run |
| CallingConvention | pwn | easy | READY | |
| CommunicationSkills | misc | easy | READY | Adjust time allowed if there is high server latency |
| cryptojail | misc/crypto | easy | READY | |
| FPU | pwn | easy/intermediate | READY_NEEDS_SOLUTION | This is a modified version of calling convention, however the solution needs to be reworked because I ran into an unexpected issue with the GOT entry resolution interfering with my rop chain. Probably solvable, but I want to know for certain |
| goatsgo | reversing | easy | NOT_READY | a recreation of magicalbillygoat in go, because strings in go suck |
| javascriptjail | misc/jail | easy |  READY | this one is easy enough that it is for sure solvable, however due to limitations on the number of characters that bash will allow, the solution can currently only be solved by piping the correct value into standard input |
| MythicalClassRegistration | pwn | hard | READY_NEEDS_SOLUTION | This is pretty much ready and has been submitted to be used in a ctf already, but I haven't actually written a solution for it yet because it ended up being significantly more challenging than I originally intended. Probably solvable |
| Prints | pwn | easy/intermediate | READY_NEEDS_SOLUTION | This needs a solution to prove its solvability, but it is for sure doable |
| triplebypass | reversing | intermediate | NOT_READY | This challenge needs a full rework. I need a cleaner way to include song lyrics in the binary, and I need a better way of encoding the flag |

