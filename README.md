# CTFProblems
CTF problems that I am making/ have made in the past.

The Makefiles for these problems are mostly going to be formatted to work with [ctf-tool](https://gitlab.com/cyberatuc/ctf-tool), a command line tool for hosting ctf problems via docker that I helped write. Rather than be dependant on that tool, you can also just launch the challenges on your own machine. To make the problems work individually, you can use the following code snippet:

```
cd "$CHALLENGE_NAME"
make
python3 ../challenge-listener.py "$(cat requires-server)" 1337
```

Dockerfiles may eventually be added so that hosting the challenges with a consistent version of libc/ environment is not such a hassol.
