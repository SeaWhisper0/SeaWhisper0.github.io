# Misdirection

**Author**: carax49

## Overview

- Category: Crypto
- Description:

```text
It is not what it is.
```

## Analysis

The content of the `enc.txt` file:

```text
1000100010100000100001110100100001010010001010110001101100101010000111000001001001000100101000100100001000101110001
```

The string only uses `0` and `1`, and its length (115 characters) is a multiple of 5 — the exact signature of a **Bacon Cipher**, which encodes each letter as a 5-symbol binary sequence.

## Solution

Using any tool you like, here I used CyberChef with `Bacon Cipher Decode` and got the string

```text
SCRIPTCTFNOTWHATITSEEMS
```

![alt text](../../../images/ctf/scriptCTF2026/misdirection/image-2.png)

Remembering that flags all have the form `scriptCTF{...}`, what if I add `{}` to the string above?

```text
SCRIPTCTF{NOTWHATITSEEMS}
```

And it worked!

## Flag

```text
SCRIPTCTF{NOTWHATITSEEMS}
```