from pwn import *

p = process("./pwn_me")

def hop_in_debugger():
    p.interactive()

if __name__=='__main__':
    hop_in_debugger()
