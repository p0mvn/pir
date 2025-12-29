# Lattice-based Cryptography Primer

Lattice-based crytography is a type of cryptography that uses lattices as the underlying mathematical structure.

Latest post-quantum encryption schemes are based on lattice hardness assumptions. In turn, PIR protocols are based on these encryption schemes. 

## Short Integer Solutions (SIS) Problem

The **Short Integer Solutions (SIS)** problem is a fundamental computational problem in lattice-based cryptography, closely related to the Learning With Errors (LWE) problem.

### Problem Definition

Given:
- A random matrix **A** ∈ ℤ_q^{n × m} (n rows, m columns, entries mod q)
- A bound β > 0

**Goal**: Find a non-zero vector **z** ∈ ℤ^m such that:

1. **A · z = 0 (mod q)** — z is in the kernel of A
2. **‖z‖ ≤ β** — z is "short" (has small norm)

### Why is it Hard?

Finding *any* solution to **Az = 0** is easy (just linear algebra). The hard part is finding a **short** solution.

The difficulty comes from the connection to lattice problems:
- The set of all solutions forms a **lattice** (a discrete additive subgroup of ℝ^m)
- Finding short vectors in a lattice is believed to be computationally hard
- SIS is as hard as worst-case lattice problems like **SIVP** (Shortest Independent Vectors Problem) and **GapSVP** (Gap Shortest Vector Problem)

### Parameters

The hardness depends on the relationship between:
- **n**: security parameter (dimension)
- **m**: number of columns (typically m > n log q)
- **q**: modulus
- **β**: bound on solution norm

If β is too large, solutions are easy to find. If too small, solutions may not exist.

### Comparison with LWE

| SIS | LWE |
|-----|-----|
| Find short **z** where **Az = 0** | Find secret **s** given **As + e = b** |
| "Find a short preimage" | "Decode with noise" |
| Used for: hash functions, signatures | Used for: encryption, key exchange |

They are **dual** problems — both reduce to hard lattice problems, but from different angles.

### Applications in Cryptography

1. **Collision-resistant hash functions**: Define h(**x**) = **Ax** mod q. Finding a collision means finding **x₁ ≠ x₂** with h(**x₁**) = h(**x₂**), which means **A(x₁ - x₂) = 0** — exactly SIS!

2. **Digital signatures**: Many lattice-based signature schemes (like Dilithium, used in post-quantum standards) rely on SIS-type assumptions.

3. **Commitment schemes**: Binding property often relies on SIS hardness.

### Inhomogeneous SIS (ISIS)

A variant where instead of finding **z** with **Az = 0**, you find short **z** with:

**Az = u (mod q)**

for some target vector **u**. This is equally hard and often more useful in constructions.

### Intuition

Think of it this way: you have a system of linear equations (mod q) with many more unknowns than equations. There are infinitely many solutions, but they form a structured lattice. The "natural" solutions you'd find via Gaussian elimination have large coefficients. Finding one where all coefficients are small (bounded by β) requires essentially searching through the lattice — which is exponentially hard in the dimension.

## LWE

LWE is a computational hardness assumption - we believe certain problems are too hard for any efficient algorithm to solve. It's popular in modern crypto because it is believed to be secure even against quantum computers.

The parameters are:
- n: the dimension of the vector
- m: number of samples givent to the attacker
- q: a modulus (all arithmetic is done modulo q)
- X: an error/noise distribution

The core idea:
Given,
- Random matrix **A** of size m x n (entries mod q)
- Secret vector **s** of length n
- Small error vector **e** from X (this is noise)
- Complete random vector **r**

The LWE assumption says these two things **look the same** to any efficient algorithm:
- The vector (A, As + e)
- The vector (A, r)

In other words: if you give someone A and the product As with some small noise added, they can't tell the difference between that and just random garbage.

### LWE Security

There is no efficient adversary that can reliably tell them apart.
The security is quantified by:
- T — the attacker's running time
- ε — the attacker's "advantage" (probability of guessing correctly beyond 50%)

If the best attack running in time T can only distinguish with advantage ε (very small), then the scheme is (T, ε)-hard.

### LWE Intuition

Think of it like this: multiplying by A is a lossy operation, and adding noise e further scrambles things. Recovering s from As+e is like solving a system of linear equations where every equation has a small random error—this turns out to be extremely hard when the parameters are chosen correctly.

## Regev Encryption

Regev encryption is a type of public-key encryption that is based on the LWE assumption.

Parameters:
- (n, q, χ) — the LWE parameters from before
- p — the plaintext modulus (messages are in ℤₚ, i.e., integers 0 to p-1)
- s — the secret key, a random vector in ℤₙ_q

### Encryption

To encrypt a message μ ∈ ℤₚ:
- Pick a random vector a ∈ ℤₙ_q
- Sample a small error e from χ
- Compute the ciphertext:
```
(a, c) = (a, aᵀs + e + ⌊q/p⌋ · μ)
```

What's happening here:
- aᵀs — inner product of a and secret s (this is the "LWE part")
- + e — add noise to hide information
- + ⌊q/p⌋ · μ — encode the message by scaling it up

The factor ⌊q/p⌋ is crucial: it "lifts" the message into a higher range so it survives the noise.
  
### Decryption

Someone with secret s decrypts by:
- Compute: `c - aᵀs mod q`
- This gives: `e + ⌊q/p⌋ · μ`
- Round to the nearest multiple of ⌊q/p⌋
- Divide by ⌊q/p⌋ to recover μ

VisuaL
```
|-------|-------|-------|-------| ... |-------|
0     ⌊q/p⌋   2⌊q/p⌋  3⌊q/p⌋         (p-1)⌊q/p⌋

      μ=1       μ=2      μ=3           μ=p-1
```

The message μ determines which "slot" you land in. The error e is small, so it just wobbles you around within your slot - rounding recovers which slot you're in.


### Correctness Condition

Decryption works if and only if:
```
|e| < ½ · ⌊q/p⌋
```

If the error is too large, you might "wobble" into the wrong slot and decrypt to the wrong message. The correctness error δ is the probability this happens.

### Additive Homomorphism

This is the magic property that makes Regev encryption useful for PIR:

Given two ciphertexts:
- (a₁, c₁) encrypting μ₁
- (a₂, c₂) encrypting μ₂
Their component-wise sum (a₁ + a₂, c₁ + c₂) decrypts to μ₁ + μ₂!

Why it works:
```
(c₁ + c₂) - (a₁ + a₂)ᵀs 
= (e₁ + ⌊q/p⌋·μ₁) + (e₂ + ⌊q/p⌋·μ₂)
= e₁ + e₂
```

The errors accumulate (e₁ + e₂), so you can only do this a limited number of times before errors grow too large and decryption fails.

### Summary

Key: s <- random vector in ℤₙ_q
Encrypt(μ): (a, aᵀs + e + ⌊q/p⌋ · μ)
Decrypt(a,c): round((c - aᵀs) / ⌊q/p⌋)
Add ciphertexts: (a₁ + a₂, c₁ + c₂) -> decrypts to μ₁ + μ₂

## Ring-LWE

Ring-LWE (Ring Learning With Errors) is a structured variant of LWE that offers significant efficiency improvements while maintaining strong security guarantees.

In standard LWE, we work with:
- A random matrix A ∈ ℤ_q^{n x m}
- A secret vector s ∈ ℤ_q^n
- A small error vector e ∈ ℤ_q^n

The LWE problem is to distinguish (A, A*s + e) from uniform randomness.

Key characteristics:
- Matrix A has no special structure
- Storage O(n*m) elements
- Computation O(n*m) operations for matrix-vector multiplication

### Ring-LWE

Ring-LWE replaces unstructured matrices with polynomial rings:

The Ring: R_q = Z_q[X]/(X^n + 1) where n is a power of two.

Instead of vectors and matrices, we work with polynomials:
- a(x) ∈ R_q^n (a random polynomial)
- s(x) ∈ R_q (the secret polynomial with small coefficients)
- e(x) ∈ R_q (the error polynomial with small coefficients)

The LWE problem becomes: distinguish (A, A*s + e) from uniform randomness.

The Ring-LWE problem is to distinguish (a, a·s + e) from uniform in R_q × R_q.

### Key Differences

| Aspect           | LWE                    | Ring-LWE                         |
|------------------|------------------------|----------------------------------|
| Structure        | Random matrices        | Polynomial rings                 |
| Public key size  | O(n²)                  | O(n)                             |
| Computation      | O(n²) matrix multiply  | O(n log n) via NTT/FFT           |
| Security basis   | Unstructured lattices  | Ideal lattices                   |

### Why Ring-LWE is Faster

Multiplication in R_q = Z_q[x]/(x^n + 1) has special structure:
1. Negacyclic convolution: Multiplying by X^i "rotates" coefficients with sign flips.
2. NTT acceleration: The Number Theoretic Transform (NTT, like FTT for final fields) reduces polynomial multiplication from O(n²) to O(n log n).

A single polynomial a(X) in Ring-LWE implicitly defines an entire nxn matrix in LWE (a circulant-like structure), but we only store n coefficients.

### Security Relationship

Ring-LWE's security relies on the hardness of problems in ideal lattices (lattices with additional algebraic structure). The relationship to LWE security:
- **Worst-case to average-case**: Ring-LWE has quantum reductions from worst-case problems on ideal lattices (SVP in ideal lattices)
- **More structure = potential weakness?**: The ring structure theoretically gives attackers more to exploit, but no practical attacks have emerged
- **Practical security**: Ring-LWE is considered secure for appropriate parameters, and is used in post-quantum standards like Kyber/ML-KEM

## LWE-to-RLWE Packing

You have d separate LWE ciphertexts, each encrypting a single value μ₁, μ₂, ..., μ_d. You want to pack them into a single RLWE ciphertext that encrypts the polynomial:

```
μ(x) = μ₁ + μ₂x + μ₃x² + ⋯ + μ_d x^(d-1)
```

This achieves ~d/2× compression (from d(d+1) elements to 2d elements).

### Step 1: Understanding the Ring R_q = Z_q[x]/(x^d + 1)

This ring contains polynomials of degree < d, where arithmetic is done modulo q and modulo (x^d + 1).

The key rule: **x^d = -1**

```
Example with d=4:
x⁴ = -1
x⁵ = x · x⁴ = -x
x⁶ = -x²
etc.
```

### Step 2: What Happens When You Multiply by x

Take a polynomial s(x) = s₀ + s₁x + s₂x² + s₃x³

Multiply by x:
```
x · s(x) = s₀x + s₁x² + s₂x³ + s₃x⁴
         = s₀x + s₁x² + s₂x³ + s₃(-1)    ← using x⁴ = -1
         = -s₃ + s₀x + s₁x² + s₂x³
```

**Result**: Coefficients rotate right, and the one that "wraps around" gets negated.

| Before | s₀ | s₁ | s₂ | s₃ |
|--------|----|----|----|----|
| After  | -s₃ | s₀ | s₁ | s₂ |

### Step 3: Building the Negacyclic Matrix

If we apply this rotation repeatedly:

```
s(x)      → coefficients: [ s₀,  s₁,  s₂,  s₃]
x·s(x)    → coefficients: [-s₃,  s₀,  s₁,  s₂]
x²·s(x)   → coefficients: [-s₂, -s₃,  s₀,  s₁]
x³·s(x)   → coefficients: [-s₁, -s₂, -s₃,  s₀]
```

Stack these as rows → **negacyclic matrix rot(s)**:

```
        [  s₀   s₁   s₂   s₃ ]
rot(s) =[ -s₃   s₀   s₁   s₂ ]
        [ -s₂  -s₃   s₀   s₁ ]
        [ -s₁  -s₂  -s₃   s₀ ]
```

### Step 4: The Key Property

**Claim**: rot(s) · v = coefficients of s(x) · v(x)

Let's verify with v = [v₀, v₁, v₂, v₃]ᵀ representing v(x) = v₀ + v₁x + v₂x² + v₃x³

The i-th row of rot(s) represents xⁱ · s(x).

So:
```
rot(s) · v = v₀ · (row 0) + v₁ · (row 1) + v₂ · (row 2) + v₃ · (row 3)
           = v₀ · s(x) + v₁ · x·s(x) + v₂ · x²·s(x) + v₃ · x³·s(x)
           = s(x) · (v₀ + v₁x + v₂x² + v₃x³)
           = s(x) · v(x)
```

**Matrix-vector multiplication = Polynomial multiplication!**

### Step 5: Recall LWE Ciphertexts

An LWE ciphertext is:
```
(a, b) where b = ⟨a, s⟩ + e + m
```
- a ∈ Z_q^d (random vector)
- s ∈ Z_q^d (secret key)
- ⟨a, s⟩ = a₀s₀ + a₁s₁ + ... + a_{d-1}s_{d-1} (inner product)

### Step 6: Consider d LWE Ciphertexts with Special Structure

Suppose we have d LWE ciphertexts where the `a` vectors form a negacyclic matrix:

```
Ciphertext 0: a₀ = [ a₀,  a₁,  a₂,  a₃],  b₀ = ⟨a₀, s⟩ + e₀ + m₀
Ciphertext 1: a₁ = [-a₃,  a₀,  a₁,  a₂],  b₁ = ⟨a₁, s⟩ + e₁ + m₁
Ciphertext 2: a₂ = [-a₂, -a₃,  a₀,  a₁],  b₂ = ⟨a₂, s⟩ + e₂ + m₂
Ciphertext 3: a₃ = [-a₁, -a₂, -a₃,  a₀],  b₃ = ⟨a₃, s⟩ + e₃ + m₃
```

Notice: These `a` vectors are exactly the rows of rot(a) for polynomial a(x) = a₀ + a₁x + a₂x² + a₃x³

### Step 7: Stack the Inner Products

Compute all inner products at once:
```
[⟨a₀, s⟩]   [  a₀   a₁   a₂   a₃ ] [ s₀ ]
[⟨a₁, s⟩] = [ -a₃   a₀   a₁   a₂ ] [ s₁ ]
[⟨a₂, s⟩]   [ -a₂  -a₃   a₀   a₁ ] [ s₂ ]
[⟨a₃, s⟩]   [ -a₁  -a₂  -a₃   a₀ ] [ s₃ ]

            = rot(a) · s
            = coefficients of a(x) · s(x)
```

### Step 8: This IS an RLWE Ciphertext!

The d LWE ciphertexts together give us:
```
a(x) = a₀ + a₁x + a₂x² + a₃x³

b(x) = b₀ + b₁x + b₂x² + b₃x³
     = (⟨a₀,s⟩ + e₀ + m₀) + (⟨a₁,s⟩ + e₁ + m₁)x + ...
     = a(x)·s(x) + e(x) + m(x)
```

This is exactly the RLWE encryption formula!

### Step 9: The Payoff

| Without packing | With packing |
|-----------------|--------------|
| d separate LWE ciphertexts | 1 RLWE ciphertext |
| d separate decryptions | 1 polynomial decryption |
| d × (d+1) scalars to transmit | 2 polynomials (2d scalars) |

**The negacyclic structure is what makes the d LWE ciphertexts "compatible" with RLWE algebra.**

### The Problem with Naive Packing

The packing above only works when the `a` vectors are **rotations of a single polynomial**. But in real PIR:

- The server computes responses using matrix-vector products
- Each response LWE ciphertext has a **random, unstructured** `a` vector
- These `a` vectors have NO relationship to each other

We need a way to pack **arbitrary** LWE ciphertexts into RLWE.

## Key Switching: Packing Arbitrary LWE Ciphertexts

Key switching solves the problem of converting LWE ciphertexts with arbitrary `a` vectors into RLWE ciphertexts.

### The Core Idea

Any vector `a = [a₀, a₁, ..., a_{d-1}]` can be written as a linear combination of basis vectors:

```
a = a₀·[1,0,0,...] + a₁·[0,1,0,...] + a₂·[0,0,1,...] + ...
```

**Key insight**: If we know how to handle each basis vector separately, we can handle ANY vector by scaling and adding!

The client pre-computes "helper ciphertexts" for each basis position. The server uses these helpers to convert any LWE ciphertext.

### Concrete Example: d=2

Let's work through the smallest possible example with actual numbers.

**Setup:**
```
Dimension: d = 2
Modulus: q = 97 (small prime for easy arithmetic)
Ring: R = Z_97[x]/(x² + 1)

LWE secret vector:  s = [3, 7]
Ring secret polynomial:  S(x) = 3 + 7x  (same numbers as polynomial)
```

**The LWE ciphertext we want to convert** (encrypting message μ = 5):
```
a = [11, 4]    ← random vector (NOT structured!)
c = ⟨a, s⟩ + μ
  = 11·3 + 4·7 + 5
  = 33 + 28 + 5
  = 66

Ciphertext: (a, c) = ([11, 4], 66)
```

Verify decryption: `c - ⟨a, s⟩ = 66 - 61 = 5 ✓`

### Step 1: Client Creates Helper Ciphertexts

The client (who knows `s`) creates RLWE encryptions of each secret component.

**Helper for s[0] = 3:**
```
Pick random A₀(x) = 2 + 5x

Compute B₀(x) = A₀(x)·S(x) + s[0]
             = (2 + 5x)·(3 + 7x) + 3

Expand the product:
  (2 + 5x)·(3 + 7x) = 6 + 14x + 15x + 35x²
                    = 6 + 29x + 35x²

Apply x² = -1 (ring reduction):
                    = 6 + 29x - 35
                    = -29 + 29x

Add s[0] = 3:
  B₀(x) = -29 + 29x + 3 = -26 + 29x = 71 + 29x  (mod 97)

Helper 0: KS₀ = (A₀, B₀) = (2 + 5x, 71 + 29x)
```

**Helper for s[1] = 7:**
```
Pick random A₁(x) = 6 + 2x

Compute B₁(x) = A₁(x)·S(x) + s[1]
             = (6 + 2x)·(3 + 7x) + 7

Expand:
  (6 + 2x)·(3 + 7x) = 18 + 42x + 6x + 14x²
                    = 18 + 48x + 14·(-1)
                    = 18 + 48x - 14
                    = 4 + 48x

Add s[1] = 7:
  B₁(x) = 4 + 48x + 7 = 11 + 48x

Helper 1: KS₁ = (A₁, B₁) = (6 + 2x, 11 + 48x)
```

**The client sends KS₀ and KS₁ to the server (this is the "key switching key").**

### Step 2: Server Performs Key Switch

The server has:
- LWE ciphertext: `(a, c) = ([11, 4], 66)`
- Helper keys: `KS₀ = (2 + 5x, 71 + 29x)` and `KS₁ = (6 + 2x, 11 + 48x)`

**Server computes the output RLWE ciphertext:**

```
A'(x) = a[0]·A₀(x) + a[1]·A₁(x)
      = 11·(2 + 5x) + 4·(6 + 2x)
      = (22 + 55x) + (24 + 8x)
      = 46 + 63x

C'(x) = c - a[0]·B₀(x) - a[1]·B₁(x)
      = 66 - 11·(71 + 29x) - 4·(11 + 48x)
      = 66 - (781 + 319x) - (44 + 192x)
      = 66 - 781 - 44 - (319 + 192)x
      = -759 - 511x
      = 17 + 71x  (mod 97)
```

**Output RLWE ciphertext: (A', C') = (46 + 63x, 17 + 71x)**

### Step 3: Client Decrypts RLWE

The client decrypts using the formula: `C'(x) + A'(x)·S(x)`

```
First compute A'(x)·S(x):
  (46 + 63x)·(3 + 7x) = 138 + 322x + 189x + 441x²
                      = 138 + 511x + 441·(-1)
                      = 138 + 511x - 441
                      = -303 + 511x
                      = 85 + 26x  (mod 97)

Now add C'(x):
  C'(x) + A'(x)·S(x) = (17 + 71x) + (85 + 26x)
                     = 102 + 97x
                     = 5 + 0x  (mod 97)
                     = 5  ✓
```

**We recovered the original message μ = 5!**

### Why It Works: The Algebra

Let's trace through why the math works out:

```
C' + A'·S 
= [c - a[0]·B₀ - a[1]·B₁] + [a[0]·A₀ + a[1]·A₁]·S

Rearrange:
= c - a[0]·B₀ - a[1]·B₁ + a[0]·A₀·S + a[1]·A₁·S
= c - a[0]·(B₀ - A₀·S) - a[1]·(B₁ - A₁·S)

Recall how we constructed B_i:
  B_i = A_i·S + s[i]
  So: B_i - A_i·S = s[i]

Substitute:
= c - a[0]·s[0] - a[1]·s[1]
= c - ⟨a, s⟩
= μ  ✓
```

The key switching keys encode the secret in a way that lets the server "cancel out" the LWE inner product term.

### Summary Table

| Step | Who | What | Data |
|------|-----|------|------|
| 1 | Client | Create RLWE encryptions of each s[i] | KS₀, KS₁, ..., KS_{d-1} |
| 2 | Client | Send key switching keys to server | (this increases query size) |
| 3 | Server | Receive arbitrary LWE ciphertext | (a, c) |
| 4 | Server | Compute weighted sum of KS keys | A' = Σ a[i]·KS_i.A |
| 5 | Server | Compute C' component | C' = c - Σ a[i]·KS_i.B |
| 6 | Server | Output RLWE ciphertext | (A', C') |
| 7 | Client | Decrypt using ring secret S | μ = C' + A'·S |

### The Noise Problem and Gadget Decomposition

In the example above, we multiplied RLWE ciphertexts by scalars like a[0] = 11.

**Problem**: In real crypto, a[i] can be as large as q (e.g., 2³²). RLWE ciphertexts contain noise, and multiplying by 2³² amplifies the noise by 2³² → **destroys the ciphertext**.

**Solution: Gadget Decomposition**

Instead of one helper per position, create helpers for each "digit" of the scalar.

Pick base B = 256. Any number v can be written as:
```
v = v⁽⁰⁾ + v⁽¹⁾·256 + v⁽²⁾·256² + v⁽³⁾·256³
```
where each v⁽ℓ⁾ ∈ {0, 1, ..., 255} is small.

Pre-compute helpers for each digit position:
```
KS[i][0] = RLWE.Enc(s[i] · 1)
KS[i][1] = RLWE.Enc(s[i] · 256)
KS[i][2] = RLWE.Enc(s[i] · 256²)
KS[i][3] = RLWE.Enc(s[i] · 256³)
```

The server decomposes a[i] into digits and computes:
```
Σ_ℓ a[i]⁽ℓ⁾ · KS[i][ℓ]
```

Now we only multiply by small numbers (0-255), keeping noise under control.

### Size of Key Switching Material

This is why YPIR queries are larger than SimplePIR/DoublePIR:

```
For d positions × k digits per scalar:
  Total KS entries: d × k RLWE ciphertexts
  Each RLWE ciphertext: 2d coefficients
  
  Total size: O(d² · k) coefficients
```

For typical parameters (d ≈ 2048, k ≈ 4), this is several megabytes of key material that must be included in the query.

### Packing Multiple LWE Ciphertexts

To pack d LWE ciphertexts into different "slots" of an RLWE ciphertext, we need key switching keys for each target slot j:

```
For slot j, we need KS_j[i] = RLWE.Enc(s[i] · x^j)
```

This places the message in the coefficient of x^j in the output polynomial.

The full packing procedure:
```
result = (0, 0)  // zero RLWE ciphertext

for j in 0..d:
    // Pack the j-th LWE ciphertext into slot j
    (a_j, c_j) = LWE_ciphertexts[j]
    
    // Key switch using slot-j keys
    A' += Σ_i a_j[i] · KS_j[i].A
    C' += c_j · x^j - Σ_i a_j[i] · KS_j[i].B

return (A', C')
```

The result decrypts to μ₀ + μ₁x + μ₂x² + ... + μ_{d-1}x^{d-1}, with all messages packed into one ciphertext.
