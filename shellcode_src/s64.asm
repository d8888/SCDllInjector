use64	
   ;!!!!! NOTICE: 8bit alignment issue will kill you
   ;Always keep register 16 byte aligned or fxsave in rtlcapturecontext() WILL KILL YOU
   push  rax rbx rcx rdx rbp rdi rsi
   push  r8 r9 r10 r11 r12 r13 r14 
   lea   rax,[rip] ;rip points to nop
next:
   nop   
   mov   rbx, rax
   mov   rax, string - next
   movzx rax, al
   add   rax, rbx
   mov   rcx, [rax] ;fastcall convetion, move first argument into rcx
   mov   rax, func - next
   movzx rax, al

   add   rax, rbx
   mov   rax, [rax]
   ; for fast call convetion, create a 32 byte shadow store
   sub   rsp, 32
   call  rax  
   add   rsp, 32
   pop       r14 r13 r12 r11 r10 r9 r8
   pop   rsi rdi rbp rdx rcx rbx rax
   ; return
   ret
func     dq  0x1122334455667788         
string   dq  0xDEADBEEF55665566