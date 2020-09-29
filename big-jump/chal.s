jmp Fcfcd208
Fc4ca423:
    
    push 0x17a7364
    xor dword  [rsp], 0x1010101
    
    push 1 
    pop rax
    push (1) 
    pop rdi
    push 3
    pop rdx
    mov rsi, rsp
    syscall
    jmp Fc81e728

F8f14e45:
    
    push 0x16f3076
    xor dword  [rsp], 0x1010101
    
    push 1 
    pop rax
    push (1) 
    pop rdi
    push 3
    pop rdx
    mov rsi, rsp
    syscall
    jmp Fc9f0f89

Fa87ff67:
    
    push 0x15e786d
    xor dword  [rsp], 0x1010101
    
    push 1 
    pop rax
    push (1) 
    pop rdi
    push 3
    pop rdx
    mov rsi, rsp
    syscall
    jmp Fe4da3b7

Fc9f0f89:
    
    push 0x7d
    
    push 1 
    pop rax
    push (1) 
    pop rdi
    push 1
    pop rdx
    mov rsi, rsp
    syscall
jmp end
Feccbc87:
    
    push 0x1636c32
    xor dword  [rsp], 0x1010101
    
    push 1 
    pop rax
    push (1) 
    pop rdi
    push 3
    pop rdx
    mov rsi, rsp
    syscall
    jmp Fa87ff67

Fcfcd208:
    
    push 0x1637862
    xor dword  [rsp], 0x1010101
    
    push 1 
    pop rax
    push (1) 
    pop rdi
    push 3
    pop rdx
    mov rsi, rsp
    syscall
    jmp Fc4ca423

Fe4da3b7:
    
    push 0x1755e35
    xor dword  [rsp], 0x1010101
    
    push 1 
    pop rax
    push (1) 
    pop rdi
    push 3
    pop rdx
    mov rsi, rsp
    syscall
    jmp F1679091

F1679091:
    
    push 0x15e3269
    xor dword  [rsp], 0x1010101
    
    push 1 
    pop rax
    push (1) 
    pop rdi
    push 3
    pop rdx
    mov rsi, rsp
    syscall
    jmp F8f14e45

Fc81e728:
    
    push 0x1727235
    xor dword  [rsp], 0x1010101
    
    push 1 
    pop rax
    push (1) 
    pop rdi
    push 3
    pop rdx
    mov rsi, rsp
    syscall
    jmp Feccbc87
end:
