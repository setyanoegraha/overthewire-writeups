# Krypton Level 0: Welcome to Cryptography

## The Setup
| Level | Username | SSH Command |
| :--- | :--- | :--- |
| Level 0 | - | - |

**Introduction:** Welcome to Krypton, OverTheWire's cryptography focused wargame. Level 0 is designed as a gentle introduction to the world of encoding and decoding. This first challenge teaches us the fundamental difference between encoding and encryption, and introduces us to Base64, one of the most common encoding schemes you'll encounter in security work.

---

## Hunting for Clues

The level information gives us a clear challenge right from the start:

> Welcome to Krypton! The first level is easy. The following string encodes the password using Base64:
> 
> `S1JZUFRPTklTR1JFQVQ=`
> 
> Use this password to log in to krypton.labs.overthewire.org with username krypton1 using SSH on port 2231. You can find the files for other levels in /krypton/

The challenge is straightforward. I have a Base64 encoded string, and I need to decode it to get the password for the next level. The key word here is "encodes" not "encrypts." This is an important distinction in cryptography.

### Understanding Base64

Base64 is an encoding scheme, not an encryption algorithm. Here's the difference:

**Encoding** is about representing data in a different format. It's completely reversible without any secret key. Base64 converts binary data into ASCII text using a specific alphabet of 64 characters (A-Z, a-z, 0-9, +, /). The equals sign (=) is used for padding.

**Encryption** is about transforming data to hide its meaning. You need a secret key to reverse the process. Without the key, the data should be unreadable.

Base64 is commonly used for:
- Embedding binary data in text formats (like images in HTML)
- Encoding credentials in HTTP Basic Authentication
- Representing data in URLs or email safely
- Storing binary data in JSON or XML

The telltale sign of Base64 is the character set it uses and the padding. The string `S1JZUFRPTklTR1JFQVQ=` ends with an equals sign, which is a strong indicator of Base64 encoding.

## Breaking In

Decoding Base64 is trivial with command line tools. On Linux, the `base64` command handles both encoding and decoding. The `-d` flag tells it to decode instead of encode.

I ran the command to decode the string:

```bash
┌──(ouba㉿CLIENT-DESKTOP)-[/tmp/krypton]
└─$ echo 'S1JZUFRPTklTR1JFQVQ=' | base64 -d
KRY[REDACTED]
```

Perfect! The decoded password is `KRY[REDACTED]`.

The command breaks down like this:
- `echo 'S1JZUFRPTklTR1JFQVQ='` - Outputs the Base64 string
- `|` - Pipes the output to the next command
- `base64 -d` - Decodes the Base64 input

The output is immediate and clear: `KRY[REDACTED]`

Now I could use this password to SSH into the next level:

```bash
ssh krypton1@krypton.labs.overthewire.org -p 2231
```

When prompted for the password, I entered `KRY[REDACTED]` and gained access to Level 1.

### Why This Matters

While this level is simple, it teaches an important security concept: **encoding is not security**. I've seen real world applications that mistakenly believe Base64 provides security. It doesn't. Anyone can decode Base64 instantly without any special tools or knowledge.

Common mistakes I've encountered:
- Storing passwords in Base64 thinking they're "encrypted"
- Using Base64 to "hide" API keys in client side JavaScript
- Thinking URL encoding or hex encoding provides security
- Believing obfuscation equals protection

None of these provide real security. If you need to protect data, use proper encryption with a strong algorithm and secure key management. If you just need to represent data in a compatible format, encoding is fine, but don't rely on it for confidentiality.

### Additional Tools for Base64

Beyond the command line `base64` tool, there are many ways to work with Base64:

**Python:**
```python
import base64
encoded = 'S1JZUFRPTklTR1JFQVQ='
decoded = base64.b64decode(encoded)
print(decoded.decode('utf-8'))  # KRY[REDACTED]
```

**JavaScript:**
```javascript
let encoded = 'S1JZUFRPTklTR1JFQVQ=';
let decoded = atob(encoded);
console.log(decoded);  // KRY[REDACTED]
```

**Online Tools:**
Websites like base64decode.org or CyberChef can decode Base64, but for security work, I prefer using local tools to avoid sending potentially sensitive data to third party services.

**Burp Suite Decoder:**
If you're doing web application testing, Burp Suite has a built in decoder that handles Base64 and many other encoding schemes.

### Moving Forward

Krypton is all about cryptography and cryptanalysis. As the levels progress, we'll encounter classical ciphers like Caesar cipher, substitution ciphers, Vigenère cipher, and more. The skills you develop here transfer directly to real world security work:

- Recognizing encoding schemes
- Identifying cipher types
- Frequency analysis
- Known plaintext attacks
- Cryptographic weaknesses

This first level sets the foundation by teaching us to distinguish between encoding (reversible, no key needed) and encryption (requires a key). As we move forward, we'll deal with increasingly complex cryptographic challenges that require analysis, programming, and creative problem solving.

---

## The Loot

**Next Level Password:** KRY[REDACTED]

**Quick Recap:** Base64 encoded string was decoded using the base64 command line tool to reveal the password for accessing the next level via SSH.
