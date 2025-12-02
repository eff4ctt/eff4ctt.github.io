---
title: My First CTF Writeup
date: 2023-10-27
description: A walkthrough of a basic buffer overflow challenge.
---

# Introduction

This is a sample writeup to demonstrate the blog's capabilities.

## The Challenge

We were given a binary and the source code.

```c
#include <stdio.h>
#include <string.h>

void win() {
    printf("You won!\n");
}

void vuln() {
    char buffer[64];
    gets(buffer);
}

int main() {
    vuln();
    return 0;
}
```

## The Solution

The `gets` function is vulnerable to buffer overflow. We can overwrite the return address to jump to `win`.

**Steps:**
1. Find the offset.
2. Find the address of `win`.
3. Construct the payload.

That's it!
