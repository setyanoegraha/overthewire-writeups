# Krypton Level 1: ROT13 and the Caesar Cipher

## The Setup
| Level | Username | SSH Command |
| :--- | :--- | :--- |
| Level 1 | krypton1 | ssh krypton1@krypton.labs.overthewire.org -p 2231 |

**Introduction:** Level 1 introduces us to one of the oldest and simplest encryption methods in history: the rotation cipher, specifically ROT13. This challenge teaches us about Caesar ciphers and why simple substitution ciphers are fundamentally weak. It's a gentle introduction to cryptanalysis, where we learn that some "encryption" methods are barely more secure than encoding.

---

## Hunting for Clues

After logging in with the password from Level 0, I found myself in the krypton1 home directory. The level information told me:

> The password for level 2 is in the file 'krypton2'. It is 'encrypted' using a simple rotation. It is also in non-standard ciphertext format. When using alpha characters for cipher text it is normal to group the letters into 5 letter clusters, regardless of word boundaries. This helps obfuscate any patterns. This file has kept the plain text word boundaries and carried them to the cipher text. Enjoy!

I started by reading the README file in the `/krypton/krypton1/` directory:

```bash
krypton1@krypton:/krypton/krypton1$ cat README
Welcome to Krypton!

This game is intended to give hands on experience with cryptography
and cryptanalysis.  The levels progress from classic ciphers, to modern,
easy to harder.

Although there are excellent public tools, like cryptool,to perform
the simple analysis, we strongly encourage you to try and do these
without them for now.  We will use them in later excercises.

** Please try these levels without cryptool first **


The first level is easy.  The password for level 2 is in the file
'krypton2'.  It is 'encrypted' using a simple rotation called ROT13.
It is also in non-standard ciphertext format.  When using alpha characters for
cipher text it is normal to group the letters into 5 letter clusters,
regardless of word boundaries.  This helps obfuscate any patterns.

This file has kept the plain text word boundaries and carried them to
the cipher text.

Enjoy!
```

The README gives us critical information:
- The password is in a file called `krypton2`
- It's encrypted using ROT13
- The ciphertext preserves word boundaries (unusual for proper cipher text)

### Understanding ROT13

ROT13 is a special case of the Caesar cipher where each letter is rotated by 13 positions. The beautiful thing about ROT13 is that it's its own inverse. Since the alphabet has 26 letters, rotating by 13 twice brings you back to the original letter:

```
A → N → A
B → O → B
C → P → C
...
Z → M → Z
```

This means the same operation both encrypts and decrypts. It's elegant but completely insecure. ROT13 was never intended for real security. It's mainly used to obscure spoilers, puzzle solutions, or offensive content in a way that's trivially reversible.

### Caesar Cipher Background

The Caesar cipher, named after Julius Caesar who allegedly used it, is a substitution cipher where each letter is shifted by a fixed number of positions. ROT13 is just a Caesar cipher with a shift of 13.

The general Caesar cipher has 26 possible keys (shifts 0-25), where:
- Shift 0: No change (plaintext = ciphertext)
- Shift 13: ROT13
- Shift 25: Shift by -1

Breaking a Caesar cipher is trivial because there are only 25 meaningful possibilities to try (shift 0 doesn't encrypt anything). You can either:
1. Try all 25 shifts (brute force)
2. Use frequency analysis to identify the shift
3. Use known plaintext (if you recognize a word)

First, I checked what type of file we were dealing with:

```bash
krypton1@krypton:~$ file /krypton/krypton1/krypton2
/krypton/krypton1/krypton2: ASCII text
```

Good, it's a simple text file. Now let me read the ciphertext:

```bash
krypton1@krypton:~$ cat /krypton/krypton1/krypton2
YRIRY GJB CNFFJBEQ EBGGRA
```

The ciphertext reads: `YRIRY GJB CNFFJBEQ EBGGRA`

Looking at this, I noticed the structure. There are four words, and I could already start to guess at the plaintext. The pattern `YRIRY` looks like it could be "LEVEL" with some rotation. The second word `GJB` is short and might be "TWO" or "THE". The third word `CNFFJBEQ` is longer and might be "PASSWORD".

## Breaking In

Since I knew this was ROT13, I could use the `tr` command, which translates characters. The `tr` command is perfect for ROT13 because it can map one set of characters to another.

The ROT13 transformation for both upper and lowercase letters is:
- Uppercase: `A-Z` becomes `N-ZA-M` (N through Z, then A through M)
- Lowercase: `a-z` becomes `n-za-m`

I ran the decryption:

```bash
krypton1@krypton:~$ echo "YRIRY GJB CNFFJBEQ EBGGRA" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
LEVEL TWO PASSWORD R[REDACTED]
```

Perfect! The decrypted text reads: `LEVEL TWO PASSWORD R[REDACTED]`

The password for level 2 is `R[REDACTED]`.

Let me break down the `tr` command:
- `echo "YRIRY GJB CNFFJBEQ EBGGRA"` - Outputs the ciphertext
- `|` - Pipes it to the next command
- `tr 'A-Za-z' 'N-ZA-Mn-za-m'` - Translates characters
  - First argument `'A-Za-z'`: The input character set (all letters)
  - Second argument `'N-ZA-Mn-za-m'`: The output character set (rotated by 13)

The `tr` command works character by character:
- Y (25th letter) → L (12th letter)
- R (18th letter) → E (5th letter)
- I (9th letter) → V (22nd letter)
- And so on...

### Verifying the Logic

Let me manually verify one word to understand the rotation:

YRIRY → LEVEL
- Y (position 25) + 13 = 38, wrap around: 38 - 26 = 12 → L
- R (position 18) + 13 = 31, wrap around: 31 - 26 = 5 → E
- I (position 9) + 13 = 22 → V
- R (position 18) + 13 = 5 → E
- Y (position 25) + 13 = 12 → L

The math checks out! Each letter is shifted forward by 13 positions (with wraparound).

### Alternative Methods

There are many ways to decrypt ROT13:

**Python:**
```python
import codecs
ciphertext = "YRIRY GJB CNFFJBEQ EBGGRA"
plaintext = codecs.decode(ciphertext, 'rot_13')
print(plaintext)  # LEVEL TWO PASSWORD R[REDACTED]
```

**Online Tools:**
Websites like rot13.com can instantly decrypt ROT13, but as the README suggests, it's better to understand the underlying mechanism.

**Manual Lookup Table:**
You could create a substitution table and manually decrypt each letter, which would be tedious but educational.

**Brute Force All Rotations:**
Since Caesar ciphers only have 25 possible keys, you could try all of them:

```bash
for i in {1..25}; do
    echo "Shift $i:" $(echo "YRIRY" | tr "A-Z" "$(echo {A..Z} | tr -d ' ' | sed "s/\(.\{$i\}\)\(.*\)/\2\1/")")
done
```

But since we knew it was ROT13, the direct approach worked perfectly.

### Why ROT13 Is Insecure

ROT13 provides zero security:

1. **Single Key**: There's only one ROT13 transformation, so anyone knowing it's ROT13 can decrypt it instantly
2. **Frequency Analysis**: Letter frequencies are preserved, making it vulnerable to statistical attacks
3. **Known Algorithm**: ROT13 is widely known, so there's no security through obscurity
4. **Pattern Preservation**: Word boundaries and punctuation are unchanged, leaking structural information

ROT13 is useful for:
- Hiding spoilers in online discussions
- Obscuring email addresses from spam bots (partially)
- Puzzle games and challenges
- Teaching basic cryptography concepts

But it should never be used for actual security.

### Moving Forward

This level taught us:
- How rotation ciphers work
- The Caesar cipher family
- Using `tr` for character translation
- Why simple substitution ciphers are weak

As we progress through Krypton, we'll encounter more sophisticated ciphers that require deeper analysis, frequency analysis, and more complex cryptanalysis techniques. But the foundation is the same: understand the cipher, identify its weaknesses, and exploit them to recover the plaintext.

The next levels will likely introduce:
- More complex substitution ciphers
- Polyalphabetic ciphers (like Vigenère)
- Modern cryptographic challenges
- Statistical analysis techniques

---

## The Loot

**Next Level Password:** R[REDACTED]

**Quick Recap:** ROT13 encrypted ciphertext was decrypted using the tr command to rotate characters by 13 positions, revealing the password stored in the krypton2 file.
