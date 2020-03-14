# PWN2
Status: Solved
Flag: `ncct{d3t3ct_tr4ck_cl4ss1fy}`

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

Pulling it up in GDB abd breaking on the scanf, we are stuck in the second loop (`b *do_echo+251`). Would there be any value in getting into the other loop?

Forcing our way into the other loop with the debugger (`b *do_echo+129, set $al=0xff`), ya, we have a write-what-where scenario. 

The "where provided" is on the stack.

Thought: maybe since it is a service, it may be forking and we may be able just to cyclethe canary. --> Nope. Comissioners said no brute forcing of competition architecture.

Alright, so my progress thusfar is best outlined in the series of funcitons in `hack.py`
1. `Stack_smashing`: Able to trigger a `stack smashing detected` message
2. `stack_smashing2`: Able to precisely overwrite the canary
3. `first_loop_twice`: explored different ways of triggering the read calls or the scanf call in `do_echo`
4. `print_canary`: found how to print canary to the screen taking adavtage of the `write` call in the first conditional in `do_echo`
5. `cycle_rip`: Now that I could overwrite the canary and overwrite the stack protections, I cycled bytes to find where to overwrite RIP in my buffer
6. `take_control_rip`: After the information of the cycle, can precisely overwrite RIP and setup a call stack

Now I need to look through the same buffer I receive with the canary (basically a printout of the stack) and see if there are any addresses in there I can use to find a libc address to setup a `ret2libc`. We see there is one on the stack, 4 QWORDs beyond the canary. This address is successfully printed to the screen in the function `print_libc_addr` and confirmed in a call to `cat /proc/<PID>/maps`   

The address is consistently 138135 bytes from the base of libc.

| PID | Printed Addr | LIBC Base Addr | Difference |
|--|-|-|-|
|29434| `0x7f3e1f8abb97`| `0x7f3e1f88a000`| 138135 |
|29454| `0x7f357f585b97`| `0x7f357f564000`| 138135 |

After that, easy as using the smae offsets and ROP stack from `pwn1`.
