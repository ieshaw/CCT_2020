# PWN3
Status: Unsolved, control last 4 bytes of RIP

Start with a checksec
```
$ checksec pwn_me
[*] '/home/ubuntu/CCT_2020/PWN/pwn3/pwn_me'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Alright, tested it in the local and remote service, perform the same, lots of user input. Let's throw it in Ghidra and see if we can figure out what we are working with.

## Initial RE

The first function we really care about it `handle_stack_commands` which is reading the commands, drops a null byte at the end of the command buffer, then zeros out the buffer in preparation for the next fun. A buffer overflow won't be that straightforward since the read only takes in 2k bytes. 

Let's investigate the `stack_command` function, which takes the `client_message` (our input) as an argument.
Lots of use of `strchr`, which returns a pointer to the substring in a string, NULL if not found.  Its looking for, in order. : `\n,\r.\0,`, and replacing those with null bytes. Then it looks for the commands `name, push, pop, print` in that order, all with their own subfunction.   

### Name

The subfunction here is `set_name`. 
It creates some spacei (`malloc(0x248)`) on the heap, puts that address in a global, then the space in memory gets copied:
````
Name Buffer:
0x0: addr of function print_client
0x8: b'user'
0x48: name string (up to 0x200 bytes, as measured by strlen)[ note strlen doesnt count the terminating null byte]
```

### Push

The subfunction here is `stack_push`. This basically creates a linked list of the stack commands. Its in a globel address right before the name global.

### Pop

The subfunction here is `stack_pop`, which uses the input number to remove the said number of nodes from the linked list gerenerated by the `stack_push` command. 
Note, the conditions for popping are interesting (particularly the `isNumber` function. Not sure if that is of use, but something to keep in mind.

### Print

The subfunction here is `stack_print`.
Starts by executing the function in the name global, with the arguments from that buffer as well (very interesting). 
It then goes on to print the elements of the linked list. 

## Back to Thinking

Ok so even if I was able to do some use-after-free trickery by putting a function pointer in the name, I would need to leak some sort of adress as PIE is enabled.

## The `Stack_Print` Funcion

Ok so there is something funny going on here with a print and a write. So it prints the stack data, but also just writes a certain number of bytes. 

## Experiments

### Overflowing into the namespace on the Heap

Alright so it looks like you can start the program and not have to name yourself firsti, or you can just name yourself multiple times. Maybe you can take control of that function in the name space by either overflowing into it? 

Ok so I gave myself a name, then gave myself another name, but it still only prints the first name when I enter `name` into the prompt. What is happening here? Hopping into debugger shows that even though it prings "You have been Named!" it is actually just jopping around the conditional and not manipulating the memory.

Ok so next I want to see where on the heap we are working. Note that the name malloc call asks for `0x248` bytes, just like the push call
#### Examine the heap when name first then push
Name is allocated at `0x55a07c480260. The push space is allocated at `0x55a07c4804b0. This is a spaching of `0x250`, which is close enough for overflow....possibly.    
#### Examine the heap when push first then name
The push space is allocated at `0x55d954bee260` and the name is allocated at `0x55d954bee4b0`, again the spacing of `0x250`. Wait, there is some weird overflow going on at the backend of the heap. There are 4 A's (presumably from the stack push) that show up and the `heap_name+24a`. Is that the heap metadata for the malloc? Let's see if I can control that.  
Ok, new process, first stack push at `0x555679a20260`, putting the name at `0x555679a204b0`, which currently has 4 X's in it (the push payload had 0x244 A's, and 8 X's)!!!.And the name buffer + 0x24a has 2A's and 4 X's. This action happens with the `initial_heap_overflow` function in `hack.py`.` 

Ok, wild. So Can I overflow if I do push, name, pop, push? This happens in the function `first_name_overflow` in `hack.py`.
| Command | Malloc'd Addr | `x/2dx <name_addr>` | 
|--|--|--|
| Push | `0x559f3c4d0260` | `0x559f3c4d04b0: 0x58585858      0x00000000` |
| Name | `0x559f3c4d04b0` | `0x559f3c4d04b0: 0x3baac8a0      0x0000559f` |
| Push (after pop 1)| `0x559f3c4d0260`  | `0x559f3c4d04b0: 0x5a5a5a5a      0x0000559f` |

```
pwndbg> x/s 0x559f3c4d0260 + 0x250
0x559f3c4d04b0: "ZZZZ\237U"
```

Now if you call `print`, it will execute that address. We have control over at RIP.

#TODO: Is the heap executable? If not, can we use it as the rop chain?

## Random Thoughts
- Can manipulate the pointer in the linked list to free the name, then can write into that space on the heap with the next push?
- Do you need to trigger a connection to the server twice? It may be using the same heap space for each connection.

