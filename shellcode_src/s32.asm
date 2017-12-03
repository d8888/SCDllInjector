use32
   push  eax ebx ecx edx ebp edi esi
   call  next
next:
   pop   eax
   mov   ebx, eax
   mov   eax, string - next
   movzx eax, al
   add   eax, ebx
   mov   eax, [eax]
   push  eax
   mov   eax, func - next
   movzx eax, al
   add   eax, ebx
   mov   eax, [eax]
   call  eax
   pop   esi edi ebp edx ecx ebx eax
   ; return
   ret
func     dd 0x12345678
string   dd 0xDEADBEFF