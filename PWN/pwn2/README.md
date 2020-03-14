# PWN2
Status: Unsolved

Start with a checksec
```
$ checksec pwn_me
[*] '/home/ubuntu/CCT_2020/PWN/pwn2/pwn_me'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Pulling it up in GDB abd breaking on the scanf, we are stuck in the second loop (`b *main+251`). Would there be any value in getting into the other loop?

Forcing our way into the other loop with the debugger (`b *main+129, set $al=0xff`), ya, we have a write-what-where scenario. 

The "where provided" is on the stack.

Maybe try and get it to link a stack addr, using the scanf method and `0x1f A's`.
From there we can do longer buffer overwrites 
Thought: maybe since it is a service, it may be forking and we may be able just to cyclethe canary.
