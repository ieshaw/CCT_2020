# PWN1

With all binaries, want to start with checking the security structures
```
$ checksec pwn_me
[*] '/home/ubuntu/CCT_2020/PWN/pwn1/pwn_me'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Alright with PIE and NX, we are in for a bit of a treat possibly, but no canary so overflows are possibly.

Ok so now we just run the executable to see what we are working with
```
$ chmod u+x pwn_me
$ ./pwn_me
0x7fc9d969bca0
Cookie Monster ONLY Wants...
PROMPT>ello
PROMPT>^C
```
So we have some sort of address put out, a message, then a never eneding prompt. Does this same behavior happen on the remote service"

```
$ ping www.cybercompetitionteam.com
64 bytes from 64.227.23.177 (64.227.23.177): icmp_seq=1 ttl=38 time=8.87 ms
$ nc 64.227.23.177 1337
0x7f9a13971ca0
Cookie Monster ONLY Wants...
PROMPT>
```
Yep, behavior is the same.

Pumping the binary into Ghidra we see...
