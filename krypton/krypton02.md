# Krypton Level 2: Known Plaintext Attack on Caesar Cipher

## The Setup
| Level | Username | SSH Command |
| :--- | :--- | :--- |
| Level 2 | krypton2 | ssh krypton2@krypton.labs.overthewire.org -p 2231 |

**Introduction:** Level 2 builds on our understanding of Caesar ciphers but introduces a clever twist: we don't know the rotation key. However, we have access to an encryption oracle, a program that will encrypt anything we want using the same key. This is a classic known plaintext attack scenario where we can use the encryption tool against itself to discover the key and decrypt the target ciphertext.

---

## Hunting for Clues

After logging in with the password from Level 1, I navigated to the krypton2 directory and read the README:

```bash
krypton2@krypton:/krypton/krypton2$ cat README
Krypton 2

ROT13 is a simple substitution cipher.

Substitution ciphers are a simple replacement algorithm.  In this example
of a substitution cipher, we will explore a 'monoalphebetic' cipher.
Monoalphebetic means, literally, "one alphabet" and you will see why.

This level contains an old form of cipher called a 'Caesar Cipher'.
A Caesar cipher shifts the alphabet by a set number.  For example:

plain:  a b c d e f g h i j k ...
cipher: G H I J K L M N O P Q ...

In this example, the letter 'a' in plaintext is replaced by a 'G' in the
ciphertext so, for example, the plaintext 'bad' becomes 'HGJ' in ciphertext.

The password for level 3 is in the file krypton3.  It is in 5 letter
group ciphertext.  It is encrypted with a Caesar Cipher.  Without any
further information, this cipher text may be difficult to break.  You do
not have direct access to the key, however you do have access to a program
that will encrypt anything you wish to give it using the key.
If you think logically, this is completely easy.

One shot can solve it!

Have fun.

Additional Information:

The `encrypt` binary will look for the keyfile in your current working
directory. Therefore, it might be best to create a working direcory in /tmp
and in there a link to the keyfile. As the `encrypt` binary runs setuid
`krypton3`, you also need to give `krypton3` access to your working directory.

Here is an example:

krypton2@melinda:~$ mktemp -d
/tmp/tmp.Wf2OnCpCDQ
krypton2@melinda:~$ cd /tmp/tmp.Wf2OnCpCDQ
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ln -s /krypton/krypton2/keyfile.dat
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
keyfile.dat
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ chmod 777 .
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ /krypton/krypton2/encrypt /etc/issue
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
ciphertext  keyfile.dat
```

The README gives us critical information:
- The password is in `krypton3`, encrypted with a Caesar cipher
- We have access to an `encrypt` program that uses the same key
- We need to create a temporary working directory and symlink the keyfile
- The encrypt binary runs with setuid krypton3 privileges

### Understanding the Attack Vector

This is a perfect example of a known plaintext attack. In cryptography, a known plaintext attack occurs when an attacker has access to both plaintext and its corresponding ciphertext. In this case, we can generate our own plaintext ciphertext pairs by using the `encrypt` program.

The strategy is simple:
1. Encrypt a known plaintext (like the alphabet or a single letter)
2. Compare the plaintext to the ciphertext to determine the shift
3. Apply the reverse shift to decrypt the target ciphertext

Let me first check what files are available:

```bash
krypton2@krypton:/krypton/krypton2$ ll -a
total 36
drwxr-xr-x 2 root     root      4096 Oct 14 09:27 ./
drwxr-xr-x 9 root     root      4096 Oct 14 09:27 ../
-rwsr-x--- 1 krypton3 krypton2 16336 Oct 14 09:27 encrypt*
-rw-r----- 1 krypton3 krypton3    27 Oct 14 09:27 keyfile.dat
-rw-r----- 1 krypton2 krypton2    13 Oct 14 09:27 krypton3
-rw-r----- 1 krypton2 krypton2  1815 Oct 14 09:27 README
```

I can see:
- `encrypt` - The encryption program (setuid krypton3)
- `keyfile.dat` - The key file (readable only by krypton3)
- `krypton3` - Our target ciphertext file
- `README` - Instructions

Let me read the target ciphertext:

```bash
krypton2@krypton:/krypton/krypton2$ cat krypton3
OMQEMDUEQMEK
```

The ciphertext is `OMQEMDUEQMEK`. This is what I need to decrypt.

## Breaking In

Following the README instructions, I needed to set up a working directory where the `encrypt` program could write output. I created a temporary directory and symlinked the keyfile:

```bash
krypton2@krypton:/krypton/krypton2$ mkdir /tmp/sol_kry2
krypton2@krypton:/krypton/krypton2$ chmod 777 /tmp/sol_kry2
krypton2@krypton:/krypton/krypton2$ cd /tmp/sol_kry2
krypton2@krypton:/tmp/sol_kry2$ ln -s /krypton/krypton2/keyfile.dat
```

Let me verify the setup:

```bash
krypton2@krypton:/tmp/sol_kry2$ ll -a
total 11048
drwxrwxrwx    2 krypton2 krypton2     4096 Feb 16 08:17 ./
drwxrwx-wt 3905 root     root     11296768 Feb 16 08:17 ../
lrwxrwxrwx    1 krypton2 krypton2       29 Feb 16 08:17 keyfile.dat -> /krypton/krypton2/keyfile.dat
```

Perfect! The symlink is in place. Now I needed to create a plaintext file to encrypt. The simplest approach was to encrypt a single letter and see what it becomes. I chose 'A' because it's the first letter of the alphabet, making it easy to calculate the shift:

```bash
krypton2@krypton:/tmp/sol_kry2$ echo 'A' > test.txt
krypton2@krypton:/tmp/sol_kry2$ ll -a ; cat test.txt
total 11052
drwxrwxrwx    2 krypton2 krypton2     4096 Feb 16 08:18 ./
drwxrwx-wt 3905 root     root     11296768 Feb 16 08:18 ../
lrwxrwxrwx    1 krypton2 krypton2       29 Feb 16 08:17 keyfile.dat -> /krypton/krypton2/keyfile.dat
-rw-rw-r--    1 krypton2 krypton2        2 Feb 16 08:18 test.txt
A
```

Good! The file contains just the letter 'A'. Now I encrypted it using the provided encrypt program:

```bash
krypton2@krypton:/tmp/sol_kry2$ /krypton/krypton2/encrypt test.txt
krypton2@krypton:/tmp/sol_kry2$ ll -a
total 11056
drwxrwxrwx    2 krypton2 krypton2     4096 Feb 16 08:18 ./
drwxrwx-wt 3905 root     root     11296768 Feb 16 08:18 ../
-rw-rw-r--    1 krypton3 krypton2        1 Feb 16 08:18 ciphertext
lrwxrwxrwx    1 krypton2 krypton2       29 Feb 16 08:17 keyfile.dat -> /krypton/krypton2/keyfile.dat
-rw-rw-r--    1 krypton2 krypton2        2 Feb 16 08:18 test.txt
```

Excellent! The encrypt program created a `ciphertext` file. Notice the file is owned by krypton3 but readable by krypton2. Let me see what 'A' became:

```bash
krypton2@krypton:/tmp/sol_kry2$ cat ciphertext
Mkrypton2@krypton:/tmp/sol_kry2$
```

Perfect! The letter 'A' was encrypted to 'M'. This tells me everything I need to know about the cipher:

**Plaintext:** A (position 0)  
**Ciphertext:** M (position 12)  
**Shift:** 12 positions forward

So the cipher shifts each letter 12 positions forward in the alphabet. To decrypt, I need to shift 12 positions backward (or equivalently, 14 positions forward since 12 + 14 = 26).

Now I could decrypt the target ciphertext. Let me first read it again:

```bash
krypton2@krypton:/tmp/sol_kry2$ cat /krypton/krypton2/krypton3
OMQEMDUEQMEK
```

To decrypt with a reverse shift of 12, I used the `tr` command. The key insight is:
- The ciphertext alphabet is shifted 12 positions forward
- To reverse it, I map M-Z (positions 12-25) to A-N, and A-L (positions 0-11) to O-Z

```bash
krypton2@krypton:/tmp/sol_kry2$ echo "OMQEMDUEQMEK" | tr 'M-ZA-L' 'A-Z'
CAE[REDACTED]
```

Success! The decrypted password is `CAE[REDACTED]`.

### Understanding the Decryption

Let me break down the `tr` command:
- `echo "OMQEMDUEQMEK"` - Outputs the ciphertext
- `|` - Pipes to the next command
- `tr 'M-ZA-L' 'A-Z'` - Translates characters
  - First argument `'M-ZA-L'`: The ciphertext alphabet (shifted)
    - M-Z represents letters that were shifted from A-N
    - A-L represents letters that were shifted from O-Z
  - Second argument `'A-Z'`: The plaintext alphabet (normal order)

Let me manually verify a few letters:
- O → C: O is at position 14 in normal alphabet, shifted back 12 = position 2 = C
- M → A: M is at position 12, shifted back 12 = position 0 = A
- Q → E: Q is at position 16, shifted back 12 = position 4 = E

The mathematics checks out perfectly!

### Alternative Approaches

I could have used several other methods:

**Method 1: Encrypt the entire alphabet**
```bash
echo "ABCDEFGHIJKLMNOPQRSTUVWXYZ" > alphabet.txt
/krypton/krypton2/encrypt alphabet.txt
cat ciphertext
# Would show: MNOPQRSTUVWXYZABCDEFGHIJKL
```

This would immediately reveal the complete substitution table.

**Method 2: Brute force all possible shifts**
Since Caesar ciphers only have 25 possible keys, I could try all shifts:

```bash
for shift in {1..25}; do
    echo "Shift $shift: $(echo 'OMQEMDUEQMEK' | tr "A-Z" "$(echo {A..Z} | tr -d ' ' | sed "s/\(.\{$shift\}\)\(.*\)/\2\1/")")"
done
```

One of the outputs would be readable English.

**Method 3: Frequency analysis**
For longer ciphertext, I could use frequency analysis. The most common letter in English is 'E', so I could find the most common letter in the ciphertext and calculate the shift from there.

**Method 4: Pattern recognition**
Looking at `OMQEMDUEQMEK`, I might recognize patterns. The double letter 'QM' appearing twice could suggest a common word pattern.

### Why This Attack Works

This attack succeeds because:

1. **Access to encryption oracle**: We can encrypt arbitrary plaintext with the same key
2. **Deterministic cipher**: The same plaintext always produces the same ciphertext
3. **Simple algorithm**: Caesar cipher is a straightforward rotation
4. **Known algorithm**: We know it's a Caesar cipher, limiting possibilities to 25 keys

In real world cryptography, having access to an encryption oracle is a serious vulnerability. Modern encryption systems are designed to resist known plaintext attacks through:
- Using unpredictable initialization vectors (IVs)
- Employing complex algorithms with large key spaces
- Implementing proper key management
- Using authenticated encryption

### Security Lessons

This level teaches several important security principles:

**Don't use weak ciphers**: Caesar ciphers provide essentially no security. Even without access to the encryption program, the cipher could be broken in seconds.

**Encryption oracle attacks**: Allowing users to encrypt arbitrary data with a secret key can leak information about that key.

**Key reuse**: Using the same key for multiple encryptions without proper safeguards makes systems vulnerable.

**Security through obscurity fails**: Even though we couldn't read the keyfile directly, we could still break the cipher because the algorithm itself is weak.

### Moving Forward

This level demonstrated that access to an encryption oracle combined with a weak cipher makes breaking encryption trivial. As we progress through Krypton, we'll encounter:
- More complex substitution ciphers
- Polyalphabetic ciphers that change the substitution
- Statistical analysis techniques
- Modern cryptographic challenges

The next levels will require deeper analysis and more sophisticated cryptanalysis tools.

---

## The Loot

**Next Level Password:** CAE[REDACTED]

**Quick Recap:** By using the provided encrypt binary as an encryption oracle to encrypt a known plaintext ('A'), the 12 position Caesar cipher shift was discovered and used to decrypt the target ciphertext with the tr command.
