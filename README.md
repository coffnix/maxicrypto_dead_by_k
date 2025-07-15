# ☠ maxicrypto_dead_by_k

This code contains intentional traps! only those who truly understand the math and C++ behind ECDSA will know how to use it. :D

**Proof of concept for exploiting reused `k` values in ECDSA signatures** — the classic vulnerability that allows full private key recovery if the same nonce is used twice.

Bitcoin maximalists have ignored this mathematical timebomb for years. This repo documents the exact derivation and provides the equations to recover `sk` (secret key) from two signatures using the same `k`.

---

## Explanation of the ECDSA Equation Derivation with Nonce Reuse (k)

In ECDSA (Elliptic Curve Digital Signature Algorithm), a signature for a message with hash `h` consists of `(r, s)`, where:

- `r = (k•G)x mod n` (the x-part of the resulting point of scalar multiplication, where `G` is the generator of the curve and `n` is the curve order).
- `s = k⁻¹ • (h + r • sk) mod n`, where `sk` is the private key and `k` is the random nonce (must be unique per signature).

If the same nonce `k` is reused for two different signatures (for hashes `h1` and `h2`), it results in the same `r` for both, with different `s1` and `s2`. This allows recovery of `sk` as follows:

1. **Write the equations for both signatures:**

```
s1 = k⁻¹ • (h1 + r • sk) mod n
s2 = k⁻¹ • (h2 + r • sk) mod n
```

2. **Multiply both equations by `k`** (eliminating the inverse):

```
s1 • k = h1 + r • sk mod n
s2 • k = h2 + r • sk mod n
```

3. **Subtract the second equation from the first:**

```
s1 • k - s2 • k = h1 - h2 mod n
k • (s1 - s2) = h1 - h2 mod n
k = (h1 - h2) / (s1 - s2) mod n
```

4. **Now substitute `k` back into one of the original equations** (using the first one, for example):

```
s1 • k = h1 + r • sk mod n
sk = (s1 • k - h1) / r mod n
```

5. **To obtain an equivalent form directly eliminating `k`:**

- Multiply the first equation by `s2`:

```
s1 • s2 • k = s2 • h1 + s2 • r • sk mod n
```

- Multiply the second equation by `s1`:

```
s2 • s1 • k = s1 • h2 + s1 • r • sk mod n
```

- Subtract the second from the first:

```
s1 • h2 - s2 • h1 = r • sk • (s1 - s2) mod n
sk = (s1 • h2 - s2 • h1) / (r • (s1 - s2)) mod n
```

This is the solution to recover `sk`. The vulnerability has been known for years and highlights the critical importance of cryptographically secure, unique nonces in ECDSA.

---

## Reminder

> If your crypto relies on "randomness" to be secure, and you f*** up randomness, you're dead.  
>  
> Bitcoin maximalists, this is your daily reminder that `k` reuse = cryptographic suicide.

---

by: Área31 Hackerspace: https://area31.net.br
