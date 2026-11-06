# HiCyberCon CTF 2026 - Full Reverse Engineering Sweep

**Author**: fatfish

## Overview

- **Event:** HiCyberCon / hiCTF (2026-10-31)
- **Result:** 7 challenges solved — 4 medium, 3 hard; the entire Reverse Engineering category
- **Shared tooling:** radare2, Unicorn, z3, Python 3 (`struct`/`hashlib`), UPX, Erlang/OTP `beam_disasm`

| # | Challenge | Difficulty | Core technique |
|---|-----------|------------|----------------|
| 1 | Cold Beacon | medium | Nim binary; anti-debug TracerPid; 23 XOR/SUM/PRODUCT constraints mod 256; SHA-256 counter-mode keystream; embedded digest as oracle |
| 2 | epsilon-drift | medium | gfortran binary; linear system mod 2^13 over IEEE-754 bit-fields; the −0.0 and 1-ULP drift traps of 1.1+2.2 |
| 3 | night-batch | medium | GnuCOBOL packed-decimal; 23 MOD 10/100 checks; patch + ptrace differential trace to extract the coefficient matrix; z3 |
| 4 | signal-lock | medium | Erlang/OTP 26+ BEAM bytecode; beam_disasm; inverting a 64-bit mix (xor/mul/rot/add); SHA-256 keystream from the token |
| 5 | Entitlement | hard | Mangled UPX magic (HI4!); anti-debug VM bytecode (self-hash); GF(2^64) 13th root; ECDLP on an anomalous curve — Smart's attack |
| 6 | Last Execution | hard | Custom VM EXE-9 whose manual lies about 3 constants; fast-forwarding a 2×10¹³-iteration loop via LCG period; self-modifying HALT chain; SEAL-256 |
| 7 | rev-obs (Sentinel Gateway) | hard | Control-flow flattening; ten 4-byte chunks through 5 number-theory gates (algebra, Pohlig–Hellman dlog, EC over F(10⁹+7)); Unicorn oracle |

## Cold Beacon (medium)

### Summary

A stripped Nim binary ("beacon") carries a 47-byte encrypted config that only prints for the right 24-character key. The key is gated by an anti-debug check and 23 table-driven arithmetic constraints (mod-256 XOR/SUM/PRODUCT over key bytes); the config is XOR-encrypted with a SHA-256 counter-mode keystream derived from the key and verified against an embedded SHA-256 digest. Because the sum-chain constraints leave only 3 free key bytes, the whole keyspace collapses to ~2304 candidates and the embedded digest acts as a perfect oracle — the unique surviving key decrypts the flag.

### Solution

#### Step 1: Recon and control flow

`file` shows a stripped, non-PIE x86-64 ELF (base 0x400000); Nim runtime strings (`syncio.nim`, `cmdline.nim`) identify the compiler. In Nim binaries the program logic lives in `NimMainModule`, reached via `main` → `NimMain` (`0x404515`) → `0x404271`. That function:

1. requires exactly one argv element of length **24** (`cmp qword [var_10h], 0x18`);
2. calls an anti-debug (`fcn.00403aec`) that reads `/proc/self/status`, locates `TracerPid:`, and requires the value `0`;
3. validates the key with `fcn.00403cff` and `fcn.00403dc4` (must return true/1);
4. decrypts and verifies the config, printing it only if `SHA256(config)` matches a 32-byte digest at `0x405e20`.

#### Step 2: The validator and the crypto

`fcn.00403cff` is a tiny constraint VM: 23 iterations, each with an opcode (`0x406070`), operand count (`0x406050`), up to 6 operand indices into the key (`0x405fc0`), and a target byte (`0x405fa0`). Opcode semantics from the disassembly: `0/3/5` → XOR-fold of operands, `1/4` → SUM mod 256, `2` → PRODUCT of the first two operands mod 256. Decoded, the system is:

- 13 **SUM chains** (`c1`–`c13`) chaining `k[9]+k[10]=0xa8 … k[23]+k[0]=0xa9`
- **PRODUCT** cross-checks: `k[3]·k[15]=0xc0`, `k[7]·k[21]=0x83`, `k[11]·k[19]=0x24`
- **XOR** checks: `k[4]^k[12]^k[20]=0`, `k[2]^k[10]^k[18]=0x6c`, and 6-byte XOR/SUM mixes (`c19`–`c22`)
- `fcn.00403dc4` adds three checks that duplicate `c1`, `c3`, `c17`

The crypto is standard: `d = SHA256(key)`, keystream `K = SHA256(d‖be32(0)) ‖ SHA256(d‖be32(1)) ‖ …` (47 bytes), `config = enc ⊕ K` with `enc` at `0x405e40`. I confirmed the model byte-for-byte by patching a copy of the binary (NOP the two validator jumps, force the anti-debug branch, NOP the final digest jump) and comparing its decrypted output for a known test key against the Python model — the keystreams matched exactly.

#### Step 3: Collapse the keyspace and let the digest pick the key

The 13 sum-chains mean every byte from `k[9]` around to `k[0]` is an affine function of just **three free head bytes** (`k[9]`, `k[12]`, `k[16]`). The PRODUCT constraints eliminate almost all `(a, c)` pairs, `c21` pins `b`, and the remaining single-byte constraints have closed-form solutions (e.g. `k[7]` = modular inverse of `k[21]` scaled by `0x83`). Enumerating that space yields ~2304 keys passing all constraints; each is run through the KDF and checked against the embedded digest — exactly one survives:

```python
#!/usr/bin/env python3
"""cold-beacon full solve: tables, ciphertext and digest are parsed straight
out of the challenge binary (non-PIE, file offset = vaddr - 0x400000)."""
import hashlib

data = open("cold-beacon", "rb").read()
o = lambda v: v - 0x400000
ENC = data[o(0x405E40):o(0x405E40) + 47]            # enc[i] = config[i] ^ K[i]
DIG = data[o(0x405E20):o(0x405E20) + 32]            # SHA256(config)
TGT = data[o(0x405FA0):o(0x405FA0) + 23]            # constraint targets
CNT = data[o(0x406050):o(0x406050) + 23]            # operand counts
OPC = data[o(0x406070):o(0x406070) + 23]            # opcodes: 0/3/5=xor 1/4=sum 2=prod
OPS = data[o(0x405FC0):o(0x405FC0) + 23 * 6]        # operand index rows (6 slots)

def check(k):  # faithful mirror of fcn.00403cff
    for i in range(23):
        ops, t, op = OPS[i*6:i*6 + CNT[i]], TGT[i], OPC[i]
        if op in (0, 3, 5):
            acc = 0
            for j in ops: acc ^= k[j]
            if acc != t: return False
        elif op in (1, 4):
            acc = 0
            for j in ops: acc = (acc + k[j]) & 0xFF
            if acc != t: return False
        elif op == 2 and (k[ops[0]] * k[ops[1]]) & 0xFF != t:
            return False
    return True  # fcn.00403dc4's extra checks duplicate c1/c3/c17

def kdf(key, n=47):
    d, out, i = hashlib.sha256(key).digest(), b"", 0
    while len(out) < n:
        out += hashlib.sha256(d + i.to_bytes(4, "big")).digest(); i += 1
    return out[:n]

def prod_solutions(x, t):  # all y with x*y == t (mod 256)
    from math import gcd
    if x == 0: return range(256) if t == 0 else []
    g = gcd(x, 256)
    if t % g: return []
    m = 256 // g
    return range(256) if m == 1 else range((t//g * pow(x//g, -1, m)) % m, 256, m)

M = 0xFF
for a in range(256):                       # k9  (head of chain c1->c2)
    k10 = (0xA8 - a) & M
    k11 = (0x74 - k10) & M
    for c in range(256):                   # k16 (head of chain c6..c13)
        k17, k18, k19 = (0xCE - c) & M, (0xA5 - (0xCE - c)) & M, (0x74 - (0xA5 - (0xCE - c))) & M
        if (k11 * k19) & M != TGT[16]: continue           # c16 product
        k20, k21 = (0x71 - k19) & M, (0x98 - (0x71 - k19)) & M
        k22, k23 = (0x94 - k21) & M, (0x99 - (0x94 - k21)) & M
        k0, k2 = (0xA9 - k23) & M, 0x6C ^ k10 ^ k18        # c13, c18
        for k7 in prod_solutions(k21, TGT[15]):            # c15: k7*k21
            for b in range(256):                           # k12 (head of c3->c5)
                k13, k14 = (0xE3 - b) & M, (0xDA - (0xE3 - b)) & M
                k15 = (0x9C - k14) & M
                if (k2 + k7 + k10 + k15 + k18 + k23) & M != TGT[21]: continue  # c21
                for k3 in prod_solutions(k15, TGT[14]):    # c14: k3*k15
                    k5 = 0x07 ^ (0x0F ^ k3 ^ k11 ^ k14 ^ k19 ^ k22)  # c22+c0
                    key = bytes([k0, 0x09 ^ k5 ^ a ^ k13 ^ k17 ^ k21,  # c20
                                 k2, k3, b ^ k20, k5, 0x07 ^ k5, k7,   # c17, c0
                                 (0xC4 - k0 - (b ^ k20) - b - c - k20) & M,  # c19
                                 a, k10, k11, b, k13, k14, k15,
                                 c, k17, k18, k19, k20, k21, k22, k23])
                    if not check(key): continue
                    cfg = bytes(e ^ s for e, s in zip(ENC, kdf(key)))
                    if hashlib.sha256(cfg).digest() == DIG:
                        print("[+] key :", key.decode())
                        print("[+] flag:", cfg.decode()); raise SystemExit
```

```text
$ python3 solve-final.py
[+] key : C0ldB34c0n::unl0ck::7a3f
[+] flag: hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}

$ ./cold-beacon 'C0ldB34c0n::unl0ck::7a3f'
hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}
```

The last command is the original, unpatched binary accepting the recovered key.

**Note for reproducibility:** verify the constraint-table bytes with `xxd`/`od` — a `radare2` `px` dump displayed two opcode bytes (`0x607e`–`0x607f`) incorrectly (shown as `01 01`, actually `02 02`), which silently turns two PRODUCT constraints into SUMs and breaks the solve.

**Tools:** radare2 (disassembly), binary patching for the model-validation oracle, Python 3.14 (`hashlib`), `xxd`/`od`.

### Flag

```text
hiCTF{c0ld_b34c0n_cfg_uns34l3d_fr0m_th3_s4mpl3}
```

## epsilon-drift (medium)

### Summary

A stripped, statically-linked gfortran binary validates a 64-hex-character "calibration vector" passed as `argv[1]`. The 32 decoded bytes are interpreted as four IEEE-754 doubles whose bit patterns must satisfy a system of linear constraints over exponent/mantissa bit-fields, an exact hardware-add check (`1.1 + 2.2` rounded to `3.3000000000000003`), and a signed-zero trap (the fourth double must be `-0.0`, not `+0.0`). With the correct vector, the binary derives a keystream from it and XOR-decrypts a blob containing the flag. The challenge name is the hint: the whole thing is about IEEE-754 edge behavior.

### Solution

#### Step 1: Locate the validator

The binary is a 1.2 MB statically-linked x86-64 ELF with no symbols and no readable program strings — every message is XOR-obfuscated with the single byte `0x6b`. Running the binary with any input prints `calibration residual out of band`; searching the file for that text under every single-byte XOR key finds it at `.rodata:0x4e34a0` (key `0x6b`), and the decode/print routine at `0x4022c0` embeds the constant `0x6b` directly.

`main` → `fcn.00401f10` is the validator:

- requires `argc - 1 == 1` (helper at `0x4087f0` returns the argument count minus one)
- fetches `argv[1]` via a `get_command_argument`-style call (`0x408820`) into a stack buffer, then requires status == 0 and length == 0x40 (exactly 64 chars)
- validates all 64 chars as hex and decodes pairs into 32 bytes: `d0`, `d1`, `d2`, `d3` (each an 8-byte little-endian u64, i.e. an IEEE-754 double)

On failure every path converges to `0x402a70(buffer, status=0)` → the XOR'd error message. On success (`status=1`), `0x402a70` runs a PBKDF-like construction: a hash (`0x402320`) of the 32 vector bytes, re-hashed with a 4-byte big-endian counter appended (36-byte input), producing a keystream that XOR-decrypts a 42-byte blob at `0x4e34ff`. Only the correct vector decrypts it to the run config containing the flag, so the constraints must be solved exactly — there is nothing to brute force.

#### Step 2: The constraint system

The check chain at `0x4020bd`–`0x402289` ANDs together a dozen `sete` results over the bit-fields of `d0` (X) and `d1` (Y) — sign `s` (bit 63), exponent `e` (bits 52–62), and the mantissa split into four 13-bit chunks `c0..c3` (bits 0–12, 13–25, 26–38, 39–51):

| Field | Constraint 1 | Constraint 2 |
|-------|--------------|--------------|
| sign  | `sign(Y) + 2·sign(X) == 0` (both positive) | |
| exp   | `(e0 + e1) & 0x7ff == 0x7ff` | `(e0 + 2·e1) & 0x7ff == 0x3ff` |
| c0    | `(u+v) & 0x1fff == 0x1334` | `(u+2v) & 0x1fff == 0xcce` |
| c1    | `(u+v) & 0x1fff == 0x1998` | `(u+2v) & 0x1fff == 0x664` |
| c2    | `(u+v) & 0x1fff == 0xccc`  | `(u+2v) & 0x1fff == 0x1332` |
| c3    | `(u+v) & 0x1fff == 0x666`  | `(u+2v) & 0x1fff == 0x999` |

Each chunk pair is two linear equations mod 0x2000 → unique solution `v ≡ B−A`, `u ≡ 2A−B`. All four chunks turn out symmetric (u = v): `0x199A, 0xCCC, 0x666, 0x333` — X and Y share one mantissa. The exponent pair solves to `e0 = 0x3ff`, `e1 = 0x400`, so `d0 = 1.1` and `d1 = 2.2`.

Two IEEE-754 traps remain:

- `d2` must equal `bits(X + Y)` as computed by hardware `addsd` — `1.1 + 2.2` is not representable and rounds to `3.3000000000000003` (0.5 ULP drift). Python floats are the same IEEE-754 doubles with round-to-nearest-even, so `struct` round-trips the exact expected bits.
- `d3` must be **`-0.0`** (`0x8000000000000000`). The `ucomisd` equality check accepts both zeros, but the status flag that unlocks the success path is produced by `cmovs` on the sign bit of `d3` — so `+0.0` passes the float comparison yet still prints the failure message. Signed zero is the gate.

Transcription note: in the second exponent check, `add r9, r14` folds the exponent sum into `r9`, which holds **e1** — the check is `e0 + 2·e1`, not `2·e0 + e1`. Getting the direction backwards passes every static re-derivation but fails at `test al, cl` (`0x402289`); an r2 breakpoint session (`r2 -d ./epsilon-drift <vector>`, break at `0x402289`, read `al`/`r9`) pins the correct orientation immediately.

#### Step 3: Solve and run

```python
#!/usr/bin/env python3
"""epsilon-drift solver: recovers the calibration vector, then lets the binary
decrypt its own run config with it. Usage: solve.py [path/to/epsilon-drift]"""
import struct, subprocess, sys

M, E = 0x2000, 0x800  # 13-bit chunk modulus, 11-bit exponent modulus

def chunk(A, B):
    """u+v ≡ A, u+2v ≡ B (mod 0x2000)  ->  v ≡ B-A, u ≡ 2A-B (mod 0x2000)."""
    v, u = (B - A) % M, (2 * A - B) % M
    assert (u + v) % M == A % M and (u + 2 * v) % M == B % M
    return u, v

# mantissa chunk targets (u+v, u+2v) from the cmp chain: bits 0-12, 13-25, 26-38, 39-51
c = [chunk(0x1334, 0x0cce), chunk(0x1998, 0x0664),
     chunk(0x0ccc, 0x1332), chunk(0x0666, 0x0999)]

# exponent: e0+e1 ≡ 0x7ff, e0+2·e1 ≡ 0x3ff (mod 0x800)  ->  e1 = 0x400, e0 = 0x3ff
e1 = (0x3ff - 0x7ff) % E
e0 = (0x7ff - e1) % E
assert (e0 + e1) % E == 0x7ff and (e0 + 2 * e1) % E == 0x3ff

mant = lambda ch: (ch[3] << 39) | (ch[2] << 26) | (ch[1] << 13) | ch[0]
d0 = (e0 << 52) | mant([t[0] for t in c])            # 1.1
d1 = (e1 << 52) | mant([t[1] for t in c])            # 2.2
fx = struct.unpack('<d', struct.pack('<Q', d0))[0]
fy = struct.unpack('<d', struct.pack('<Q', d1))[0]
d2 = struct.unpack('<Q', struct.pack('<d', fx + fy))[0]  # bits(addsd(1.1, 2.2))
d3 = 0x8000000000000000                                  # -0.0, NOT +0.0

vector = struct.pack('<QQQQ', d0, d1, d2, d3).hex()
print(f"calibration vector: {vector}")
print(f"  d0={fx!r}  d1={fy!r}  d2={fx+fy!r}  d3=-0.0")

binary = sys.argv[1] if len(sys.argv) > 1 else "./epsilon-drift"
out = subprocess.run([binary, vector], capture_output=True, text=True)
print(out.stdout.strip())
```

```bash
$ python3 solve.py ./epsilon-drift
calibration vector: 9a9999999999f13f9a999999999901406766666666660a400000000000000080
  d0=1.1  d1=2.2  d2=3.3000000000000003  d3=-0.0
hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}
```

For comparison, the identical vector ending in `+0.0` (last byte `00` instead of `80`) still prints `calibration residual out of band` — the signed-zero gate in action.

### Flag

```text
hiCTF{1eee754_s1gn3d_z3r0_1u1p_dr1ft_eps!}
```

The flag names the three techniques: IEEE 754 (`1eee754`), signed zero (`s1gn3d_z3r0`), and 1-ULP drift (`1u1p_dr1ft_eps`).

**Tools:** radare2 5.x (static disassembly + `r2 -d` breakpoint debugging), Python 3 (`struct` for exact IEEE-754 bit round-trips).

## night-batch (medium)

### Summary

A stripped x86-64 ELF that turns out to be a **GnuCOBOL-compiled** account-key validator: it reads one 18-digit CLI argument, converts it to packed-decimal, and gates on 23 arithmetic checks of the form `expr MOD 10 == const` (final check `MOD 100 == 94`). On success it XOR-decrypts a 42-byte message with a SHA-256-chained keystream derived from the key — the flag. The constraints were recovered by patching out the reject jumps and differentially tracing the libcob arithmetic dispatcher with ptrace; the system has exactly one solution in digits 0–9.

### Solution

#### Step 1: Identify the target

`file` shows a stripped, dynamically-linked ELF; strings reveal the GnuCOBOL runtime (`COB_MOUSE_FLAGS`, `GnuCOBOL information`, `cob_set_runtime_option`), and `.rodata` contains `"3.2"` with `libcob` statically linked — so no `cob_*` imports to lean on.

```bash
$ ./night-batch 123456789012345678
account rejected
```

Running it gives no hints, and neither `account` nor `rejected` appears as a plain string — all messages are XOR-encoded and rebuilt at runtime.

Key layout recovered from `main` (`0x400940`) → COBOL program at `0x400a70`:

- `ACCEPT n FROM ARGUMENT-NUMBER` → exactly one CLI argument required
- `ACCEPT arg FROM ARGUMENT-VALUE` → raw argument at `0x460140`, length must be **18**
- a byte-loop `cob_move`s each char into an 18-byte field at `0x460100`, converting ASCII digits to **packed-decimal** (`'1' → 0x1f`) — so the key is 18 digits

#### Step 2: Map the checks and the success path

The program body is 23 near-identical check blocks ending in `cmp(field@0x45e360, const)` + `jne reject`, all rejecting via `0x400b77`:

- arithmetic goes through one dispatcher `fcn.0041df30(f1, op, f2)` (op chars `'+'`, `'*'`, …) using global `cob_decimal` temps at `0x461220/0x461200`
- each block ends with `fcn.0041e530` — a **DIVIDE … REMAINDER** helper whose divisor literal field `{size=2, data="10"}` sits at `0x44cdf0` (`"100"`/size 3 for the final block) — then compares the packed work field at `0x4600e0` against a constant

The reject branch sets a flag byte at `0x4600f0` to 0 and calls the exit decoder `fcn.00402f40`; the success branch reaches it with the flag still set:

- **reject path**: `fcn.00402780` XORs a 17-byte table at `0x44d0a0` with the single byte `0x5A` → `"account rejected\n"` (verified statically)
- **success path**: 42-byte table at `0x44d0bf` XOR a keystream generated by `fcn.004027e0` — a hand-rolled **SHA-256** (H0–H7 constants visible) seeded from the key, then chained over 36-byte intermediates; the decoded message is verified via `SHA256(msg)` against 4 embedded qwords (`0x2c146846b66a3fbd`, `0x181654efa527e488`, `0x6dbc8ff6323aeadb`, `0xb0a680efaef6a08f`) and printed with `fwrite`

So there is no way around finding the exact key — the flag is encrypted with it.

#### Step 3: Extract the constraints dynamically and solve

Static reading of gcc-optimized GnuCOBOL codegen (SSE-shuffled `cob_field` structs, reused decimal temporaries) was error-prone, so the semantics were **measured** instead:

1. Copy the binary and NOP out the 24 six-byte reject jumps (`0x400c16 … 0x402424`) so every check executes regardless of input.
2. With a ptrace tracer, breakpoint the arithmetic dispatcher `0x41df30` and the 23 compare call sites; at each stop read registers and dereference the field structs (`[arg+8]` = data pointer → `0x4601xx` = key digit, `0x44a7ex` = literal) and the packed result at `0x4600e0`.
3. Run a zero baseline `000000000000000000` plus 18 unit vectors (digit *i* = 1, rest 0). Because every block's value is linear in the key digits, `WK(E_i) - WK(Z) mod 10` yields the exact coefficient matrix — 21 pure-linear blocks (zero baseline), plus two bilinear ones (`k1*k10`, `k1*k9`). Every constraint is of the form `expr MOD 10 == const`; the final block uses `MOD 100`: `4*k3 + 5*k6 + 5*k10 + 2*k15 + 9*k16 == 94 (mod 100)`.
4. Feed the system to z3 with all digits constrained to 0–9: it has **exactly one solution**, `481702596318740925`. The real (unpatched) binary accepts it and prints the flag.

`solve.py` (complete, needs `z3-solver` and `./night-batch` in the CWD):

```python
#!/usr/bin/env python3
import subprocess, sys
import z3

# {digit index: coefficient} per block: sum(coef*digit) % mod == const
LINEAR = [
    (2, {3: 1, 4: 1, 8: 1}, 3, 10),                # k3+k4+k8
    (3, {2: 3, 3: 1, 4: 2, 5: 3, 6: 1}, 1, 10),    # 3k2+k3+2k4+3k5+k6
    (4, {2: 1, 10: 1, 17: 1}, 7, 10),
    (5, {5: 3, 6: 1, 7: 2, 8: 3}, 7, 10),
    (6, {8: 3, 9: 1, 10: 2, 11: 3}, 7, 10),
    (7, {11: 3, 12: 1, 13: 2}, 9, 10),
    (8, {0: 1, 14: 3, 15: 1, 16: 2, 17: 3}, 2, 10),
    (9, {0: 1, 11: 1, 17: 1}, 7, 10),
    (10, {6: 1, 10: 1, 14: 1}, 6, 10),
    (11, {7: 1, 9: 1, 14: 1}, 2, 10),
    (12, {0: 1, 13: 1, 17: 1}, 3, 10),
    (13, {7: 1, 8: 1, 12: 1}, 2, 10),
    (14, {0: 1, 1: 2, 2: 3, 16: 2, 17: 3}, 2, 10),
    (15, {12: 1, 13: 2, 14: 3}, 5, 10),
    (16, {0: 1, 12: 1, 13: 1}, 5, 10),
    (17, {7: 2, 8: 3, 9: 1, 10: 2}, 1, 10),
    (18, {5: 3, 6: 1, 7: 2}, 9, 10),
    (19, {12: 1, 13: 2, 14: 3, 15: 1}, 4, 10),
    (20, {4: 1, 5: 1, 16: 1}, 4, 10),
    (22, {0: 1, 4: 1, 8: 1}, 0, 10),
    (23, {3: 4, 6: 5, 10: 5, 15: 2, 16: 9}, 94, 100),  # final check
]

k = [z3.Int(f"k{i}") for i in range(18)]
s = z3.Solver()
for d in k:
    s.add(d >= 0, d <= 9)
s.add((k[1] * k[10]) % 10 == 8)   # block 1
s.add((k[1] * k[9]) % 10 == 4)    # block 21
for _, coeffs, const, mod in LINEAR:
    s.add(sum(c * k[i] for i, c in coeffs.items()) % mod == const)

while s.check() == z3.sat:
    m = s.model()
    key = "".join(str(m.eval(v).as_long()) for v in k)
    s.add(z3.Or([v != m.eval(v) for v in k]))
    out = subprocess.run(["./night-batch", key],
                         capture_output=True, text=True, timeout=10)
    print(f"[{key}] {out.stdout.strip()}")
    if "hiCTF{" in out.stdout:
        print(f"FLAG: {out.stdout.strip()}")
        break
```

```text
$ python3 solve.py
[*] 1 solution(s) in digits 0-9
[*] candidate key: 481702596318740925
    $ ./night-batch 481702596318740925
    hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}
[+] FLAG: hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}
```

### Flag

```text
hiCTF{c0b0l_p4ck3d_d3c1mal_n1ghtly_b4tch!}
```

Key: `481702596318740925`

## signal-lock (medium)

### Summary

A stripped Erlang/OTP 26+ BEAM module (`signal_lock.beam`) validates a single 8-byte session-integrity token. Disassembling the bytecode with `beam_disasm` reveals a fully invertible 64-bit mixing function (xor, odd-multiply, rotate, add — all mod 2⁶⁴); inverting it against the hard-coded target recovers the token `<<"g4m30v3r">>`. The module then decrypts the flag itself by XORing a 48-byte literal with a SHA-256 keystream derived from the token, so no Erlang runtime is needed to get the flag — pure Python reproduces the whole thing.

### Solution

#### Step 1: Get a working Erlang/OTP ≥ 26 and disassemble

`file` shows the `.beam` is gzip-wrapped; decompressed it's a standard BEAM IFF container (chunks: `Line, Type, AtU8, Code, StrT, ImpT, ExpT, LitT, Meta`). The sole interesting export is `verify/1`.

The module uses an OTP 26+ opcode (`bs_init_writable`), so an old runtime cannot even load it. With no root access, a stock Erlang was assembled without `sudo`:

```bash
apt download erlang-base erlang-crypto            # Debian trixie, OTP 27.3.4.1
dpkg -x erlang-base_*.deb root/ && dpkg -x erlang-crypto_*.deb root/
# Debian's launcher hardcodes ROOTDIR=/usr/lib/erlang — run erlexec directly:
ROOTDIR=$PWD/root/usr/lib/erlang BINDIR=$ROOTDIR/erts-15.2.7/bin \
  exec $BINDIR/erlexec -noshell -pa .
```

`beam_disasm:file("signal_lock.beam")` (ships in `compiler`) yields the complete pseudo-source. Key logic:

```erlang
verify(Token) ->
    <<N:64>> = Token,                          % unsigned big-endian 64-bit
    case transform(N) of
        12675316763487955908 -> {ok, unlock(N)};
        _                     -> {error, locked}
    end.

transform(N) ->                                % all mod 2^64
    rotl64(((N bxor 11936128517019425370)
             * 11400714819323198485) band M64, 29) + 81985529216486895.

unlock(N) ->                                   % 48-byte cipher literal from LitT
    KS = keystream(N, 48),                     % <<sha256(<<N:64, Pos:32>>) || Pos <- 0..>>
    << (C bxor K) || {C,K} <- lists:zip(cipher(), KS) >>.
```

The multiplier is `0x9E3779B97F4A7C15` (the golden-ratio constant) — odd, hence invertible mod 2⁶⁴.

#### Step 2: Invert the transform, re-derive the keystream, decrypt

Every stage of `transform` is a bijection on 64-bit words: subtract the additive constant, rotate right by 29, multiply by the modular inverse of K2, xor K1. The token lands on `0x67346d3330763372` — ASCII `g4m30v3r` — which forward-checks to the target. Reimplementing `keystream` in Python (two SHA-256 blocks suffice for 48 bytes) and XORing with the cipher literal pulled from the module's `LitT` chunk gives the flag.

```python
#!/usr/bin/env python3
"""signal-lock: signal-lock.zip -> flag (no Erlang needed)."""
import gzip, hashlib, struct, zipfile, zlib

M64 = (1 << 64) - 1
K1, K2, K3 = 11936128517019425370, 11400714819323198485, 81985529216486895
TARGET = 12675316763487955908

rotl64 = lambda x, r: ((x << r) | (x >> (64 - r))) & M64
rotr64 = lambda x, r: ((x >> r) | (x << (64 - r))) & M64
transform = lambda n: (rotl64(((n ^ K1) * K2) & M64, 29) + K3) & M64

# 1) 48-byte cipher literal from the LitT chunk of the gzip-wrapped BEAM
with zipfile.ZipFile("signal-lock.zip") as z:
    beam = gzip.decompress(z.read("signal_lock.beam"))
def chunk(name):
    pos = 12
    while pos + 8 <= len(beam):
        n, size = beam[pos:pos+4], int.from_bytes(beam[pos+4:pos+8], "big")
        if n.decode() == name: return beam[pos+8:pos+8+size]
        pos += 8 + size + ((4 - (size & 3)) & 3)          # 4-byte chunk padding
pool, pos = zlib.decompress(chunk("LitT")[4:]), 4
cipher = None
for _ in range(int.from_bytes(pool[:4], "big")):           # <len:32><ext-term>
    ln = int.from_bytes(pool[pos:pos+4], "big"); pos += 4
    e = pool[pos:pos+ln]; pos += ln
    if e[:2] == b"\x83\x6d":                               # SMALL_TUPLE+BINARY
        cipher = e[6:6+int.from_bytes(e[2:6], "big")]
assert len(cipher) == 48

# 2) invert transform: sub -> rotr -> mul-inv -> xor
N = ((rotr64((TARGET - K3) & M64, 29) * pow(K2, -1, 1 << 64) & M64)) ^ K1
assert transform(N) == TARGET
token = struct.pack(">Q", N)

# 3) keystream = sha256(N || pos) blocks; flag = cipher xor keystream
ks, p = b"", 0
while len(ks) < len(cipher):
    ks += hashlib.sha256(struct.pack(">Q", N) + struct.pack(">I", p)).digest(); p += 1
print("token :", token)
print("flag  :", bytes(a ^ b for a, b in zip(cipher, ks)).decode())
```

```text
$ python3 solve.py
token : b'g4m30v3r'
flag  : hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}
```

#### Step 3: Confirm against the genuine module

Running the untouched `.beam` in OTP 27 (`signal_lock:verify(<<"g4m30v3r">>)`) returns `{ok,<<"hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}">>}`, matching the Python derivation — the disassembly read was exact. The distributed zip's SHA-256 (`93651d91…df99`) matched the challenge manifest.

### Flag

```text
hiCTF{b34m_byt3c0d3_n3v3r_l13s_s3ss10n_unl0ck3d}
```

## Entitlement (hard)

### Summary

A "licence checker" wrapped in a UPX stub whose magic was vandalised (`UPX!` → `HI4!`) so `upx -d` refuses. The unpacked binary hides a custom stack VM (whose bytecode is encrypted with a key derived from a self-hash of the interpreter, corrupted under a debugger) checking the 16-hex serial as `s ↦ (s⊕K11)^13⊕K13` in GF(2⁶⁴) — invertible with a 13th root. The 25-hex activation code is a scalar for square-and-multiply over an **anomalous elliptic curve** (`#E = p`), solved instantly with Smart's attack. The flag is then minted by a key-derivation that includes a 5×10⁸-iteration modular-multiplication "warmup", so the final step is simply letting the binary compute the flag itself with the recovered credentials.

### Solution

#### Step 1: Unpack the mangled UPX stub

`file` shows a static ELF with `memfd_create` / `/proc/self/exe` strings and no section headers — a UPX runtime stub — but `upx -t` says "NotPacked": every `UPX!` magic in the file was replaced with `HI4!` (the trailer at `0x3a9c` reads `HI4!` instead of `UPX!`). Restore the magic and UPX unpacks normally.

```bash
python3 -c "d=open('Entitlement','rb').read().replace(b'HI4!',b'UPX!');open('E.upx','wb').write(d)"
upx -d -o Licence E.upx     # 32319 <- 15048 bytes, dynamically linked, stripped
```

#### Step 2: Serial — decrypt the VM bytecode and invert GF(2⁶⁴) x↦x¹³

`main` reads a 16-hex-char serial into a u64 and requires `fcn.00404560(s) == 0x30cefbec2e4bc466`. That function is a VM interpreter (17 opcodes, 8×u64 registers, ≤100000 instructions) executing bytecode at `0x407080`. The bytecode is stored encrypted: `fcn.00404330` hashes the interpreter's own code bytes (`0x404560..0x404702`, seed `0x80a86c0cba674b51`, multiply `0x4ab4302c37aa6cbd`, fold `x^(x>>31)`), XORs the hash with `0xa66de8df3249dfe4` **if `/proc/self/status` shows `TracerPid: 1..9`**, expands it with xorshift64(10,24,11) and XOR-decrypts 396 bytes of bytecode. Replicating the clean path offline yields 99 instructions whose net effect is pure GF(2⁶⁴) arithmetic with reduction polynomial `x⁶⁴ + 0x2b395c2099596d9f`:

```text
r7 = input ^ K11;  r7 = r7^2; r7 *= r7-input? ... → r7^13;  return r7 ^ K13
```

i.e. `VM(s) = (s ⊕ K11)¹³ ⊕ K13` with `K11 = 0xd1705c3b2e33689b`, `K13 = 0xba6b1f3cb925c25a`. Since `gcd(13, 2⁶⁴−1) = 1`, invert directly:

```text
s = ((target ⊕ K13) ^ (13⁻¹ mod 2⁶⁴−1)) ⊕ K11  = 0x8f7db18bd70e193b
```

#### Step 3: Activation — recognise the anomalous curve, run Smart's attack

`main` square-and-multiplies the activation bits through `fcn.00403ad0` starting from the identity `{0,0,0,0,1}` and requires the result to equal `R`. Probing that function in Unicorn showed EC point addition: elements are 5-limb affine points `(x, y)` (the `limb4≠0` form is the point at infinity), small integers land as 2-torsion points, and all derived points satisfy

```text
y² = x³ + b·x + c  over GF(p),   p = 0x8c817b4a4c0f170cd5aab18cf  (prime)
b  = 0x65561c079c3bb669feb4d54d9,  c = 0x3905920c79c2f7ace28164fb6
A  = (0xc217d88d4bf005f2022d4e0f, 0x30999f70fb48e2b703431f4d0)
R  = (0x0622d01f78ebad9c83dd402304, 0x387932a13c1ef33f165880b6)
```

The order of `A` divides `p` (`p·A = ∞`, trace `t = 1`): an **anomalous** curve, so the ~99-bit ECDLP falls to Smart's attack — lift `A, R` to `Z/p⁵`, compute `p·Ã`, `p·R̃` projectively, and take the ratio of p-adic elliptic logs `φ = −X/Y`:

```text
k = 0x2977e17b118de75b3b4e921a4   (exactly 25 hex digits — matches the input format)
```

#### Step 4: Flag — feed the credentials back to the binary

After both checks, `main` derives the flag as `SHA-256` chains over (serial‖activation) XOR the stored 64-byte ciphertext at `0x405200` — but one derivation input is the output of `fcn.004037b0`, a Montgomery-style mixer chained through **500 000 000 self-multiplications** (≈20 minutes of CPU). The output never converges, so there is no shortcut: hand the binary its own credentials and wait. The final `sum(flag bytes) == 0x133d` check doubles as verification.

```bash
printf '8f7db18bd70e193b\n2977e17b118de75b3b4e921a4\n' | ./Licence
# Serial > Activation code > Correct! The flag is hiCTF{...}   (~20 min later)
```

Complete solve script (unpack → serial → activation → run; stages 1–3 finish in seconds):

```python
#!/usr/bin/env python3
"""hiCTF "Entitlement" — full solve."""
import hashlib, os, struct, subprocess, zipfile

M64 = (1 << 64) - 1

# ---------- Stage 1: unpack ----------
with zipfile.ZipFile("../entitlement.zip") as z:
    blob = bytearray(z.read("Entitlement"))
blob = blob.replace(b"HI4!", b"UPX!")            # restore vandalised UPX magic
for f in ("Entitlement.upx", "Licence"):
    if os.path.exists(f): os.remove(f)
open("Entitlement.upx", "wb").write(blob)
subprocess.run(["upx", "-d", "-o", "Licence", "Entitlement.upx"],
               check=True, capture_output=True)
subprocess.run(["chmod", "+x", "Licence"], check=True)
exe = open("Licence", "rb").read()

def v2o(v):  # vaddr -> file offset for the non-PIE image
    if 0x400000 <= v < 0x4007c8: return v - 0x400000
    if 0x401000 <= v < 0x40470d: return v - 0x401000 + 0x1000
    if 0x405000 <= v < 0x405b24: return v - 0x405000 + 0x5000
    if 0x406de0 <= v < 0x40720c: return v - 0x406de0 + 0x5de0
    raise ValueError(hex(v))

# ---------- Stage 2: serial = inverse of VM's GF(2^64) x^13 ----------
h = 0x80a86c0cba674b51                          # anti-tamper self-hash
for byte in exe[v2o(0x404560):v2o(0x404702)]:
    x = (byte ^ h) & M64
    x = (x * 0x4ab4302c37aa6cbd) & M64
    h = x ^ (x >> 31)
ks, x = bytearray(), h                          # xorshift64(10,24,11) keystream
while len(ks) < 0x18c:
    t = (x ^ (x >> 10)) & M64
    t = ((t << 24) & M64) ^ t
    x = (t ^ (t >> 11)) & M64
    ks += struct.pack("<Q", x)
bc = bytes(a ^ b for a, b in zip(exe[v2o(0x407080):v2o(0x407080)+0x18c], ks))
# decoded VM program: return (input ^ K11)^13 ^ K13 in GF(2^64), poly K12
K11, K12, K13 = 0xd1705c3b2e33689b, 0x2b395c2099596d9f, 0xba6b1f3cb925c25a
TARGET = 0x30cefbec2e4bc466

def gfmul(a, b):
    r = 0
    while b:
        if b & 1: r ^= a
        b >>= 1; a <<= 1
    for i in range(127, 63, -1):
        if (r >> i) & 1: r ^= (1 << i) ^ (K12 << (i - 64))
    return r

def gfpow(a, e):
    r = 1
    while e:
        if e & 1: r = gfmul(r, a)
        a = gfmul(a, a); e >>= 1
    return r

serial = gfpow(TARGET ^ K13, pow(13, -1, (1 << 64) - 1)) ^ K11
assert gfpow(serial ^ K11, 13) ^ K13 == TARGET
print(f"[+] serial     = {serial:016x}")

# ---------- Stage 3: activation = ECDLP on anomalous curve (Smart) ----------
p  = 0x8c817b4a4c0f170cd5aab18cf
b  = 0x65561c079c3bb669feb4d54d9
cc = 0x3905920c79c2f7ace28164fb6
Ax, Ay = 0xc217d88d4bf005f2022d4e0f, 0x30999f70fb48e2b703431f4d0
Rx, Ry = 0x0622d01f78ebad9c83dd402304, 0x387932a13c1ef33f165880b6
INF = (None, None)

def ecadd(P, Q):
    if P == INF: return Q
    if Q == INF: return P
    x1, y1 = P; x2, y2 = Q
    if x1 == x2:
        if (y1 + y2) % p == 0: return INF
        lam = (3*x1*x1 + b) * pow(2*y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam*lam - x1 - x2) % p
    return (x3, (lam*(x1 - x3) - y1) % p)

def ecmul(k, P):
    R = INF
    while k:
        if k & 1: R = ecadd(R, P)
        P = ecadd(P, P); k >>= 1
    return R

assert ecmul(p, (Ax, Ay)) == INF                # anomalous: #E = p

def lift(x, y, prec):                           # lift to Z/p^prec
    D = (y*y - x**3 - b*x - cc) // p % p
    return x, (y - D * pow(2*y, -1, p) % p * p) % p**prec

PIN = (0, 1, 0)
def paddp(P, Q, N):
    X1, Y1, Z1 = P; X2, Y2, Z2 = Q
    if Z1 % N == 0: return Q
    if Z2 % N == 0: return P
    u = (Y2*Z1 - Y1*Z2) % N; v = (X2*Z1 - X1*Z2) % N
    if v % N == 0:
        return pdupl(P, N) if u % N == 0 else PIN
    v2 = v*v % N; v3 = v2*v % N; u2 = u*u % N; zz = Z1*Z2 % N
    return (v*((u2*zz - v2*(X1*Z2 + X2*Z1)) % N) % N,
            (u*((2*X1*v2*Z2 + v2*X2*Z1 - u2*zz) % N) - Y1*v3*Z2) % N,
            v3*zz % N)
def pdupl(P, N):
    X1, Y1, Z1 = P
    if Z1 % N == 0: return PIN
    n = (3*X1*X1 + b*Z1*Z1) % N; d = (2*Y1*Z1) % N
    if d % N == 0: return PIN
    d2 = d*d % N
    return (d*((n*n*Z1 - 2*X1*d2) % N) % N,
            (n*((3*X1*d2 - n*n*Z1) % N) - Y1*d2*d) % N,
            d2*d*Z1 % N)
def pmulp(k, P, N):
    R = PIN
    while k:
        if k & 1: R = paddp(R, P, N)
        P = pdupl(P, N); k >>= 1
    return R

def vint(x):
    v = 0
    while x % p == 0 and x > 0:
        x //= p; v += 1
    return v

PREC = 5; N = p**PREC
Al = lift(Ax, Ay, PREC); Rl = lift(Rx, Ry, PREC)
pA = pmulp(p, (Al[0], Al[1], 1), N)
pR = pmulp(p, (Rl[0], Rl[1], 1), N)
phiP = (-pA[0] * pow(pA[1], -1, N)) % N          # p-adic elliptic log -X/Y
phiR = (-pR[0] * pow(pR[1], -1, N)) % N
v = min(vint(phiP), vint(phiR))
N2 = p**(PREC - v)
act = (phiR // p**v) * pow(phiP // p**v, -1, N2) % N2 % p
assert ecmul(act, (Ax, Ay)) == (Rx, Ry)
print(f"[+] activation = {act:025x}")

# ---------- Stage 4: binary mints the flag (~20 min KDF warmup) ----------
print("[*] running the binary (~20 min)...")
out = subprocess.run(["./Licence"], input=f"{serial:016x}\n{act:025x}\n".encode(),
                     capture_output=True, timeout=3600).stdout.decode()
flag = out.split("flag is ")[1].strip()
assert sum(flag.encode()) == 0x133d              # main's integrity check
print(f"[+] FLAG: {flag}")
```

Actual output (Stage 4 tail):

```text
Serial > Activation code > Correct! The flag is hiCTF{>o<_C0ngrats_Her3_1s_Y0ur_HI4_Subscript1on_^_^}
```

### Flag

```text
hiCTF{>o<_C0ngrats_Her3_1s_Y0ur_HI4_Subscript1on_^_^}
```

**Tools used:** UPX 4.2.4, radare2, Unicorn 2.1.4 (oracle probing), Python 3 (gmpy-free bignum, hashlib), `sympy.isprime`.

**Answer to the challenge prompt** ("I believe I have the key but why isn't it working?"): the serial alone isn't enough — the activation stage hides an ECDLP on an anomalous curve, and any debugger attached to the packed binary silently corrupts the VM bytecode via the `TracerPid` self-check, so a cracked-or-patch approach dead-ends.

## Last Execution (hard)

### Summary

`last_execution.img` is a cold dump of a custom 64-bit virtual machine ("EXE-9 CORE"): page-rotated instruction fetch, position-dependent opcode dispatch, HALT-chained code segments, rotated table reads, and a custom 16-round block cipher ("SEAL-256") sealing the flag. The embedded manual documents the machine — but lies about three constants, and the fake "operator console" register dump locks a decoy seal. The solve: correct the spec against its own encode-time traces, validate the emulator against a SHA-256 commitment, mathematically fast-forward a 2×10¹³-iteration loop, discover the final segment is entered *twice* via a self-modifying visit counter, derive the real key from the emulated terminal state, and decrypt `WILL_SEAL`.

### Solution

#### Step 1: Parse the container, then trust the traces — not the prose

The image is a trivially-parsed container: 24 segments described by a table at `0x100` (all CRCs pass), including six CODE segments, two rotated TBL segments, a plaintext `PRIMER` manual, four test seals, a `TELEMETRY` console dump, and garbage decoys. The PRIMER specifies the whole machine — fetch de-rotation chain, dispatch, ISA, HALT chaining (`next_id = imm32 ^ low32(R1)`), and the SEAL-256 cipher.

But the PRIMER's prose deliberately misstates three constants. Each lie is exposed by an "encode-time trace" in the same document, which is the intended ground truth:

| PRIMER says | Trace proves | Trace source |
|---|---|---|
| fetch-rotation init `ROL64(..., 19)` | **17** | §2.4: `ROT[1]=0x39, ROT[2]=0x37` for `EXEC_MAIN` |
| row-rotation chain `rr[i] = rr[i-1]*17 + B + i*11` | **`i*13`** | §5.2b: `rr = 31,2D,30,16` for `DSEED` |
| dispatch `idx = op + ((pc>>4) + AUX)` | **`pc>>3`** | §3.2b: `op=0x93, pc=0x40, AUX=0x47 → 0xE2 (LDRR)` |

One more trap is directional: `stored = ROL(logical, rr)` means the logical row is `stored[64-rr:]+stored[:64-rr]` (a right rotation). With these corrections, running `EXEC_SELFTEST` standalone produces `SHA256(be64(R1..R4))` exactly equal to the §6.3 commitment `0b6d8d47...bcf2` — the emulator is now provably bit-exact.

#### Step 2: Follow the chain, fast-forward the furnace, enter FINAL twice

Chained execution runs `EXEC_MAIN → FOLD_A → FOLD_B → EXEC_LIMIT`. `EXEC_LIMIT` ("the core went dark") loads `R9 = 0x123456789abc ≈ 2×10¹³` and loops that many passes stepping an 18-bit LCG (`x = x*0x19660D + 0x3C6EF35F mod 2¹⁸`) in R6's low bits while accumulating into R8. Direct emulation is hopeless, but the loop state is fully periodic: the LCG has period 2¹⁸, the R5 phase counter (+0x4001 mod 2¹⁵) period 2¹⁵, and R12 cycles mod 3 — joint period `3·2¹⁸ = 786432`. Summing one period and decomposing `N = full·P + rem` collapses 2×10¹³ passes into ~1.6M operations (verified instruction-by-instruction against the VM for several passes first).

`EXEC_FINAL` is entered **twice** — "links are data". It keeps a visit counter in its own writable code (`STW` into the filler word at `FINAL+0xd38`, right after its HALT):

- visit 1: `R11 = 0x5eed0001` → `low32(R1) = 0x5eed0001` → HALT links **back to LIMIT** (another 2×10¹³ passes)
- visit 2: `R11 = 0xa112fffb` → HALT yields `next_id = 0xFFFFFFFF` (chain end) and leaves `R15 = 'STAL'`

The `TELEMETRY` console dump is the central decoy: it claims the chain ends `FOLD_B → FINAL`, urges "do not re-derive", and hands you its register file. Its R2 is corrupted by one nibble (`...b1f14576` vs the true `...b1f15576`) — so its key opens `TEST_SEAL_2` to `hiCTF{f4k3_fl4g}` and nothing else. (The same fake flag also hides in a decoy ELF in `ARTIFACTS` and behind a single-byte XOR 0x37 in `REV_NOTES`.) Only the emulated terminal state R1–R4 derives the real key.

#### Step 3: One script — image to flag

```python
#!/usr/bin/env python3
"""
last-execution / EXE-9 CORE -- complete solve: cold image -> flag.
Usage: python3 solve_last_execution.py [path/to/last_execution.img]
"""
import struct, zlib, hashlib, sys

M64 = (1 << 64) - 1
K = 0x9E3779B97F4A7C15
X = 0xA5A5A5A5A5A5A5A5
MASK18 = (1 << 18) - 1

def rol64(v, n):
    n &= 63
    return v if n == 0 else ((v << n) | (v >> (64 - n))) & M64

def sext32(v):
    v &= 0xFFFFFFFF
    return v - (1 << 32) if v & 0x80000000 else v

class Fault(Exception):
    pass

DISPATCH = {0x03:'NOP',0x0A:'JNZ',0x0B:'LI',0x12:'JMP',0x16:'LUI',0x1D:'TRAP',
            0x21:'ORI',0x2D:'MOV',0x38:'ADD',0x42:'ADDI',0x4C:'SUB',0x55:'AND',
            0x5F:'OR',0x6A:'XOR',0x73:'XORI',0x7E:'MUL',0x87:'ROL',0x8F:'HALT',
            0x91:'ROR',0x9C:'SHL',0xA5:'SHR',0xB0:'NOT',0xBA:'LDW',0xC3:'LDB',
            0xC9:'ANDI',0xCE:'STW',0xD7:'STB',0xE2:'LDRR',0xEC:'CMP',0xF5:'JZ'}
PSH = ['NOP','XOR','ADD','MOV','ROL','SHR','AND','SUB']   # fallback, regs mod 16

class VM:
    def __init__(self, image):
        self.orig = image                     # bytes as shipped (rotation chains)
        self.mem = bytearray(image)           # mutable memory (stores visible to fetch/LDW)
        n = struct.unpack('>I', image[0x0c:0x10])[0]
        self.exec_seed  = struct.unpack('>Q', image[0x10:0x18])[0]
        self.table_seed = struct.unpack('>Q', image[0x18:0x20])[0]
        self.entry = struct.unpack('>I', image[0x20:0x24])[0]
        self.segments = {}
        for i in range(n):
            e = image[0x100 + i * 0x40: 0x100 + i * 0x40 + 0x40]
            sid, typ = struct.unpack('>II', e[0:8])
            off, size = struct.unpack('>QQ', e[8:0x18])
            flags, aux = struct.unpack('>II', e[0x18:0x20])
            self.segments[sid] = dict(id=sid, type=typ, off=off, size=size,
                                      flags=flags, aux=aux,
                                      name=e[0x24:0x34].split(b'\x00')[0].decode())
        self.regs = [0] * 16
        self.Z = 0
        self._rots, self._rrs = {}, {}

    # --- rotation chains (constants corrected per the primer's encode-time traces) ---
    def page_rots(self, seg):
        if seg['id'] not in self._rots:
            rots, m = [], rol64((self.exec_seed ^ (seg['id'] * K)) & M64, 17)  # 17, not 19
            for p in range((seg['size'] + 255) // 256):
                if p > 0:
                    w = struct.unpack('>Q', self.orig[seg['off'] + (p-1)*256:][:8])[0]
                    m = rol64(((m ^ w ^ X) * K) & M64, 31)
                rots.append(m & 63)
            self._rots[seg['id']] = rots
        return self._rots[seg['id']]

    def row_rots(self, seg):
        if seg['id'] not in self._rrs:
            rrs, rr = [], (self.table_seed ^ ((seg['id'] * 0x1BF5) & M64)) & 63
            rrs.append(rr)
            for i in range(1, seg['size'] // 64):
                B = self.orig[seg['off'] + (i - 1) * 64]           # first stored byte of row i-1
                rr = (rr * 17 + B + i * 13) & 63                   # 13, not 11
                rrs.append(rr)
            self._rrs[seg['id']] = rrs
        return self._rrs[seg['id']]

    def seg_at(self, addr):
        for s in self.segments.values():
            if s['off'] <= addr < s['off'] + s['size']:
                return s
        return None

    def fetch(self, seg, pc):
        addr = seg['off'] + pc
        raw = struct.unpack('>Q', bytes(self.mem[addr:addr + 8]))[0]
        word = rol64(raw, self.page_rots(seg)[pc >> 8])
        op, rd, ra, rb = (word >> 56) & 0xFF, (word >> 48) & 0xFF, (word >> 40) & 0xFF, (word >> 32) & 0xFF
        imm = word & 0xFFFFFFFF
        idx = (op + ((pc >> 3) + seg['aux'])) & 0xFF              # pc>>3, not pc>>4
        if idx in DISPATCH:
            mn, fb = DISPATCH[idx], False
        else:
            mn, fb = PSH[idx & 7], True
            rd, ra, rb = rd & 15, ra & 15, rb & 15                # fallback: regs mod 16
        return mn, fb, rd, ra, rb, imm

    def run_segment(self, seg, pc, max_steps=10**9, one_step=False):
        while True:
            mn, fb, rd, ra, rb, imm = self.fetch(seg, pc)
            R = self.regs
            if mn == 'NOP':
                pass
            elif mn == 'LI':   R[rd] = imm
            elif mn == 'LUI':  R[rd] = (imm << 32) & M64
            elif mn == 'ORI':  R[rd] |= imm
            elif mn == 'MOV':  R[rd] = R[ra]
            elif mn == 'ADD':  R[rd] = (R[ra] + R[rb]) & M64
            elif mn == 'SUB':  R[rd] = (R[ra] - R[rb]) & M64
            elif mn == 'AND':  R[rd] = R[ra] & R[rb]
            elif mn == 'OR':   R[rd] = R[ra] | R[rb]
            elif mn == 'XOR':  R[rd] = R[ra] ^ R[rb]
            elif mn == 'MUL':  R[rd] = (R[ra] * R[rb]) & M64
            elif mn == 'ADDI': R[rd] = (R[ra] + sext32(imm)) & M64
            elif mn == 'ANDI': R[rd] = R[ra] & imm
            elif mn == 'XORI': R[rd] = R[ra] ^ imm
            elif mn == 'ROL':  R[rd] = rol64(R[ra], imm)
            elif mn == 'ROR':  R[rd] = rol64(R[ra], -imm)
            elif mn == 'SHL':  R[rd] = (R[ra] << (imm & 63)) & M64
            elif mn == 'SHR':  R[rd] = R[ra] >> (imm & 63)
            elif mn == 'NOT':  R[rd] = R[ra] ^ M64
            elif mn in ('LDW', 'LDB', 'LDRR', 'STW', 'STB'):
                addr = (R[ra] + sext32(imm)) & M64
                if mn == 'LDRR':
                    t = self.seg_at(addr)
                    if t is None or t['type'] != 3:
                        raise Fault(f'LDRR {addr:#x} not in TBL')
                    i, k = (addr - t['off']) >> 6, (addr - t['off']) & 63
                    if k > 56:
                        raise Fault('LDRR unaligned')
                    row = self.orig[t['off'] + i * 64:][:64]
                    rr = self.row_rots(t)[i]
                    logical = row[64 - rr:] + row[:64 - rr] if rr else row  # logical = ROR(stored, rr)
                    R[rd] = struct.unpack('>Q', logical[k:k + 8])[0]
                elif mn == 'LDW':
                    R[rd] = struct.unpack('>Q', bytes(self.mem[addr:addr + 8]))[0]
                elif mn == 'LDB':
                    R[rd] = self.mem[addr]
                else:
                    t = self.seg_at(addr)
                    if t is None or not (t['flags'] & 1):
                        raise Fault(f'WRITEPROT at {addr:#x}')
                    if mn == 'STW':
                        self.mem[addr:addr + 8] = struct.pack('>Q', R[rd])
                    else:
                        self.mem[addr] = R[rd] & 0xFF
            elif mn == 'CMP':
                self.Z = 1 if R[ra] == R[rb] else 0
            elif mn in ('JZ', 'JNZ', 'JMP'):
                if mn == 'JMP' or (mn == 'JZ') == bool(self.Z):
                    pc = (pc + 8 + sext32(imm)) & M64
                    if one_step:
                        return pc, None
                    continue
            elif mn == 'HALT':
                nid = (imm ^ (R[1] & 0xFFFFFFFF)) & 0xFFFFFFFF
                return 0, (None if nid == 0xFFFFFFFF else nid)
            elif mn == 'TRAP':
                raise Fault(f'TRAP {imm:#x}')
            else:
                raise Fault(f'BADOP {mn}')
            pc += 8
            if one_step:
                return pc, None

def fast_limit(v):
    """Execute EXEC_LIMIT, fast-forwarding the ~2e13-pass loop (joint period 786432)."""
    lim = v.segments[5]
    pc = 0
    while pc != 0xb8:                                   # straight-line prologue
        pc, _ = v.run_segment(lim, pc, one_step=True)
    R6, R8, R5, R12, N = v.regs[6], v.regs[8], v.regs[5], v.regs[12], v.regs[9]

    def one_pass(R6, R8, R5, R12):                      # loop body 0xb8..0x180
        s = ((R6 & MASK18) * 0x19660D + 0x3C6EF35F) & MASK18   # 18-bit LCG on R6 low bits
        R6 = (R6 & ~MASK18 & M64) | s
        R8 = (R8 + (rol64(R6, 27) ^ R6)) & M64
        R8 = (R8 + ((R12 << 15) | R5)) & M64
        t = R5 + 0x4001                                 # R5 phase, period 2^15
        R5 = t & 0x7FFF
        if t >> 15:                                     # carry: R12 cycles mod 3
            R12 = 0 if R12 == 2 else R12 + 1
        return R6, R8, R5, R12

    P = 3 << 18                                         # lcm(2^18, 3*2^15)
    a, b, c, d = R6, R8, R5, R12
    for _ in range(P):                                  # one full period -> sum + reset check
        a, b, c, d = one_pass(a, b, c, d)
    assert (a, c, d) == (R6, R5, R12)
    period_sum = (b - R8) & M64
    full, rem = divmod(N, P)
    R8 = (R8 + full * period_sum) & M64                 # fast-forward
    for _ in range(rem):
        R6, R8, R5, R12 = one_pass(R6, R8, R5, R12)
    v.regs[6], v.regs[8], v.regs[5], v.regs[12], v.regs[9] = R6, R8, R5, R12, 0
    pc = 0x188                                          # epilogue (R1 lo=0x1337c0da; HALT -> FINAL)
    while True:
        pc, nid = v.run_segment(lim, pc, one_step=True)
        if nid is not None:
            return nid

def main(path):
    image = open(path, 'rb').read()
    assert zlib.crc32(image[:0x30]) & 0xFFFFFFFF == struct.unpack('>I', image[0x30:0x34])[0]
    v = VM(image)

    # 1) validate the emulator against the primer's SPEC SELF-CHECK commitment
    v.run_segment(v.segments[6], 0)                     # EXEC_SELFTEST standalone
    blob = b''.join(struct.pack('>Q', v.regs[i]) for i in range(1, 5))
    assert hashlib.sha256(blob).hexdigest() == \
        '0b6d8d4770eac443de6b9b73340a4a262117d9da42e6ced9411ebda286bbbcf2'

    # 2) run the HALT-chained execution path (FINAL is entered twice; LIMIT twice)
    v = VM(image)
    nid = v.entry
    while nid is not None:
        seg = v.segments[nid]
        nid = fast_limit(v) if seg['name'] == 'EXEC_LIMIT' else v.run_segment(seg, 0)[1]
    assert v.regs[15] == 0x5354414C                      # 'STAL' success marker

    # 3) SEAL-256: SBOX from DLOOK logical rows 0..3, key from terminal R1..R4
    rows = b''
    dl = v.segments[11]
    for i in range(4):
        row = image[dl['off'] + i * 64:][:64]
        rr = v.row_rots(dl)[i]
        rows += row[64 - rr:] + row[:64 - rr] if rr else row
    perm = list(range(256))                              # Fisher-Yates keyed by D
    for i in range(255, 0, -1):
        j = rows[i] % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    sbox = perm
    inv_sbox = [0] * 256
    for x in range(256):
        inv_sbox[sbox[x]] = x

    key = hashlib.sha256(b'LASTEXEC' + struct.pack('>4Q', *v.regs[1:5]) + b'LASTEXEC').digest()
    x = list(struct.unpack('>4Q', key))                  # key schedule -> 17 round keys
    rks = []
    for i in range(1, 18):
        for j in range(4):
            t = (x[j] + x[(j + 1) % 4] + (K * (4 * (i - 1) + j + 1)) & M64) & M64
            t ^= x[(j + 3) % 4] >> 7
            x[j] = rol64(t, 13)
        rks.append(struct.pack('>Q', x[0] ^ x[2]) + struct.pack('>Q', x[1] ^ x[3]))

    P_fwd = [0x00,0x05,0x0A,0x0F,0x04,0x09,0x0E,0x03,0x08,0x0D,0x02,0x07,0x0C,0x01,0x06,0x0B]
    P_inv = [0x00,0x0D,0x0A,0x07,0x04,0x01,0x0E,0x0B,0x08,0x05,0x02,0x0F,0x0C,0x09,0x06,0x03]
    seg = v.segments[20]                                 # WILL_SEAL: 16 shift bytes + 4 blocks
    data = image[seg['off']:seg['off'] + seg['size']]
    shifts, L = data[:16], (seg['size'] - 16) // 16
    stored = [data[16 + r * 16:32 + r * 16] for r in range(L)]
    ct = [bytearray(16) for _ in range(L)]               # undo column rotation
    for r in range(L):
        for c in range(16):
            ct[(r - shifts[c]) % L][c] = stored[r][c]
    out = b''
    for blk in ct:                                       # SEAL-256 decrypt block
        st = bytearray(blk)
        for t in range(16):
            st[t] ^= rks[16][t]
        for r in range(15, -1, -1):
            st = bytearray(bytes(st[P_inv[t]] for t in range(16)))
            for t in range(16):
                st[t] = inv_sbox[st[t]]
            for t in range(16):
                st[t] ^= rks[r][t]
        out += bytes(st)
    pad = out[-1]
    assert 1 <= pad <= 16 and out[-pad:] == bytes([pad]) * pad   # PKCS#7 validates the key
    print(out[:-pad].decode())

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'extracted/last_execution.img')
```

```text
$ python3 solve_last_execution.py last_execution.img
hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}
```

Runtime ≈ 2 minutes on Python 3 (dominated by the two period simulations of 786 432 passes each; the ~2×10¹³ actual passes are never executed).

### Flag

```text
hiCTF{3x3c_9_r3m3mb3rs_4ll_but_th3_l4st_h4lt_l13s}
```

Flag text ("exec 9 remembers all, but the last halt lies") confirms the intended lesson: the terminating HALT of `EXEC_FINAL` — reached only on its second visit, with the true register state — is the sole honest record of the run. The `TELEMETRY` console dump, the `TEST_SEAL`s, and the GARB segments were all decoys.

## rev-obs / Sentinel Gateway (hard)

### Summary

A control-flow-flattened x86-64 passkey checker where the passkey **is** the flag: a 47-char `hiCTF{...}` string whose ten 4-byte chunks each feed a different number-theoretic gate (quadratic pair, discrete logs mod 2³¹−1, linear system mod 2³²−5, sum+product quadratic, and a point on an elliptic curve over F(10⁹+7)). Every gate is invertible analytically once the flattened state machine is decoded, so the flag drops out of pure algebra — the only dynamic work needed was extracting three loop constants via a small Unicorn oracle.

### Solution

#### Step 1: Structure — passkey = flag, ten 4-byte chunks

Stripped ELF, strings show `hiCTF Sentinel Gateway` / `Passkey:` / `hiCTF{` / `strncmp`. From `objdump -d -M intel`:

- Length gate at `0x401187`: `cmp rax, 0x2e` **after** `rax--` and newline stripping ⇒ **47 chars**.
- `strncmp(buf, "hiCTF{", 6)` and `buf[46] == '}'`.
- Body = `buf[6..45]` = 40 bytes = ten little-endian dwords ("chunks") at offsets 6,10,…,42, loaded at `0x4011c2`–`0x401326`.

Obfuscation: a state machine dispatches through tables at `0x4030e0`–`0x403180` whose index-0 entries (`0x6b3e91f2 → 0x19c45d80 → 0x43b7e025 → 0x51e29f3a → 0x3d087b16 → 0x38a5f41c`) are the only real path; junk entries are `XXbadc0d` markers. Each stage ORs `(computed ^ target)` differences and uses `acc % 7 + 1` as the dispatch index — **all gates must hold exactly**, otherwise the machine lands on a `badc0d` state and denies. `0x4028f0` is `__umodti3`, so the recurring `imul/mul/call` idiom is `(a*b) mod M` for three prime moduli: `0x7fffffff`, `0x3b9aca07` (10⁹+7), `0xfffffffb`.

That yields one equation set per chunk pair:

| Chunks (flag offsets) | Gate | Modulus |
|---|---|---|
| c6=`[6]`, c10=`[10]` | `c6·c10 ≡ 0x37c0f52c`; `c6² − 31337·c10² ≡ 0x1e054920` | 2³¹−1 |
| c14, c18 | `c18² ≡ c14³ + 0x20a6e·c14 + 0x30730db7` **and** EC loop below | 10⁹+7 |
| c22, c26 | `7^c22 ≡ 0x7bb949ec`; `11^c26 ≡ 0xb3bbfc8` | 2³¹−1 |
| c30, c34 | `0xcc1321·c30 + 0x3ade68b1·c34 ≡ 0x92660155`; `0x75bcd15·c30 + 0x211ecd59·c34 ≡ 0x7da7aac3` | 2³²−5 |
| c38, c42 | `(c38+c42) ≡ 0x4770c967`; `(c38·c42) ≡ 0x2e97d196`; `isprime(c38^9)`, `isprime(c42^0x11)` (`0x402010` = Miller-Rabin) | 2³¹−1 |

#### Step 2: The elliptic-curve stage and the self-verifying flag

`0x402220` is an EC point op (24-byte structs `{x, y, flag}`, `{0,0,1}` = identity) on `y² = x³ + 0x20a6e·x + 0x30730db7` over F(10⁹+7). Stage `0x19c45d80` runs an 11-round square-and-multiply (exponent `0x539` = 1337) over base point `P0 = (123456789, 0x0e42882f)` (`0x403230`); the final call adds `Z = (c14 mod p3, c18 mod p3)` and the result must equal `T = (0x2d0c1bbd, 0x205c7191)` — so `Z = T − R`, where `R` is the loop's accumulated point. Calls 0–11 are input-independent (verified by probing with an emulator), so `R = (0x026278ec, 0x388397e4)` is just a constant.

After all gates, a 32-byte key (seeded with the MD5 IV constants `67452301 efcdab89 98badcfe 10325476`, XORed with stage constants and `(c6<<32|c10)`, `(c38<<32|c42)`, permuted by the 8-round ARX mix at `0x401f80` after each stage) XOR-decrypts a 98-byte ciphertext at `0x4031a0`, gated by a Java-style `acc = byte + 31·acc` checksum (`0xb4f079c8`) — and the plaintext is the success message that itself contains the flag, so the binary confirms the recovered passkey.

Methodology note: every constant above was cross-checked with a ~100-line **Unicorn** oracle (start at `0x4011be` past `strncmp`, hook the dispatch/decrypt/call sites) rather than trusted from hand-transcription — two hex digits misread by hand (`0x0e42882f`, `0x20a6e = 133742`) had sent the curve fits down dead ends until constants were re-derived programmatically.

#### Step 3: Solve

```python
#!/usr/bin/env python3
# rev-obs solver: recovers the 47-char passkey (= flag) from constants in ./challenge.
# Pure algebra; the binary itself is the final verifier.
import subprocess, math

P1, P2, P3 = 0x7fffffff, 0xfffffffb, 1000000007      # gate moduli (2^31-1, 2^32-5, 1e9+7)
EC_A, EC_B = 0x20a6e, 0x30730db7                     # curve y^2 = x^3 + a*x + b over F(P3)
R  = (0x026278ec, 0x388397e4)                        # EC-loop accumulated point (input-independent)
T  = (0x2d0c1bbd, 0x205c7191)                        # required loop result

def pr4(v):                                          # dword -> 4 printable ASCII chars (LE)
    b = v.to_bytes(4, "little")
    return b if all(0x20 <= c <= 0x7e for c in b) else None

def is_prime(n):                                     # deterministic MR for 32-bit
    if n < 2: return False
    for sp in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % sp == 0: return n == sp
    d, s = n - 1, 0
    while d % 2 == 0: d //= 2; s += 1
    for a in (2,3,5,7,11,13,17,19,23,29,31,37):
        x = pow(a, d, n)
        if x in (1, n-1): continue
        for _ in range(s-1):
            x = x*x % n
            if x == n-1: break
        else: return False
    return True

# --- chunks c6, c10: c6*c10 = T1, c6^2 - 31337*c10^2 = T2  (mod P1) ---
T1, T2 = 0x37c0f52c, 0x1e054920
# c6 = T1/c10  =>  31337*u^2 + T2*u - T1^2 = 0 with u = c10^2; P1 = 3 mod 4
disc = (T2*T2 + 4*31337*T1*T1) % P1
assert pow(disc, (P1-1)//2, P1) == 1
sq = pow(disc, (P1+1)//4, P1)
ai = pow(2*31337, -1, P1)
for c10sq in ((-T2 + sq)*ai % P1, (-T2 - sq)*ai % P1):   # u = c10^2
    if pow(c10sq, (P1-1)//2, P1) != 1: continue
    v = pow(c10sq, (P1+1)//4, P1)                    # c10 = sqrt(u)
    for c10 in (v, P1-v):
        c6 = T1 * pow(c10, -1, P1) % P1
        if pr4(c6) and pr4(c10) and c6*c10 % P1 == T1:
            sol_c6, sol_c10 = pr4(c6), pr4(c10)
assert sol_c6 == b"m4th" and sol_c10 == b"_c0n"
# -> "m4th", "_c0n"

# --- chunks c22, c26: 7^c22 = 0x7bb949ec, 11^c26 = 0xb3bbfc8  (mod P1) ---
# P1-1 = 2 * 3^2 * 7 * 11 * 31 * 151 * 331 is smooth -> Pohlig-Hellman
def dlog(g, h, p):
    n, fac = p - 1, [(2,1),(3,2),(7,1),(11,1),(31,1),(151,1),(331,1)]
    res = []
    for q, e in fac:
        m = q**e
        gq, hq = pow(g, n//m, p), pow(h, n//m, p)    # subgroup of order m (m <= 9)
        cur, d = 1, 0                                # brute-force subgroup dlog
        while cur != hq: cur, d = cur*gq % p, d + 1
        res.append(d)
    X, M = 0, 1
    for r, (q, e) in zip(res, fac):                  # CRT recombination
        m = q**e
        X += M * ((r - X) * pow(M, -1, m) % m); M *= m
    assert pow(g, X, p) == h
    return X
sol_c22, sol_c26 = pr4(dlog(7, 0x7bb949ec, P1)), pr4(dlog(11, 0xb3bbfc8, P1))
# -> "w_3l", "l1pt"

# --- chunks c30, c34: 2x2 linear system (mod P2) ---
A1,B1,R1_ = 0xcc1321, 0x3ade68b1, 0x92660155
A2,B2,R2_ = 0x75bcd15, 0x211ecd59, 0x7da7aac3
det = (A1*B2 - A2*B1) % P2
c30 = ((R1_*B2 - R2_*B1) * pow(det, -1, P2)) % P2
c34 = ((A1*R2_ - A2*R1_) * pow(det, -1, P2)) % P2
assert (A1*c30 + B1*c34) % P2 == R1_ and (A2*c30 + B2*c34) % P2 == R2_
sol_c30, sol_c34 = pr4(c30), pr4(c34)                # -> "1c_d", "log_"

# --- chunks c38, c42: sum + product -> quadratic roots, primality fixes order ---
S, Q = 0x4770c967, 0x2e97d196
disc = (S*S - 4*Q) % P1
r = pow(disc, (P1+1)//4, P1); assert r*r % P1 == disc
r1, r2 = (S + r) * pow(2, -1, P1) % P1, (S - r) * pow(2, -1, P1) % P1
assert is_prime(r1 ^ 9) and is_prime(r2 ^ 0x11)
sol_c38, sol_c42 = pr4(r1), pr4(r2)                  # -> "4f7b", "2c9e"

# --- chunks c14, c18: Z = T - R on the curve; c1x = Z.x (or +P3 if printable) ---
def padd(P, Q):
    x1,y1,x2,y2 = *P, *Q
    if x1 == x2 and (y1+y2) % P3 == 0: return None
    l = ((3*x1*x1 + EC_A) * pow(2*y1, -1, P3) if P == Q   # doubling: (3x^2+a)/(2y)
         else (y2-y1) * pow(x2-x1, -1, P3)) % P3          # addition: chord
    x3 = (l*l - x1 - x2) % P3
    return (x3, (l*(x1 - x3) - y1) % P3)
Z = padd(T, (R[0], -R[1] % P3))
x, y = Z
assert (y*y - (x**3 + EC_A*x + EC_B)) % P3 == 0       # chunk pair lies on the curve
sol_c14 = pr4(x) or pr4(x + P3)                       # -> "tr0l"
sol_c18 = pr4(y) or pr4(y + P3)                       # -> "_fl0"

flag = ("hiCTF{m4th_c0n".encode() + sol_c14 + sol_c18 + b"w_3ll1pt1c_dlog_"
        + sol_c38 + sol_c42 + b"}").decode()
print(flag)

out = subprocess.run(["./challenge"], input=flag + "\n", capture_output=True, text=True)
print(out.stdout.strip())
assert "ACCESS GRANTED" in out.stdout
```

Output:

```text
$ python3 solve.py
hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}
=== [ hiCTF Sentinel Gateway ] ===
Passkey:
[+] ACCESS GRANTED! Passkey verified.
[+] Flag: hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}
```

### Flag

```text
hiCTF{m4th_c0ntr0l_fl0w_3ll1pt1c_dlog_4f7b2c9e}
```

