# 🕵️‍♂️ **CTF Notes – Translation, Encoding & Steganography**

---

## 1️⃣ Leet Speak (1337)

**Challenge:**

```text
c4n y0u c4p7u23 7h3 f149?
```

**Translation:**

* Leet speak replaces letters with numbers or symbols.
* ✅ Result:

```text
can you capture the flag?
```

---

## 2️⃣ Binary

**Challenge:**

```text
01101100 01100101 01110100 01110011 00100000 01110100 01110010 01111001 00100000 01110011 01101111 01101101 01100101 00100000 01100010 01101001 01101110 01100001 01110010 01111001 00100000 01101111 01110101 01110100 00100001
```

**Solution:**

* Convert binary → decimal → ASCII.
* ✅ Result:

```text
lets try some binary out!
```

---

## 3️⃣ Base32

**Challenge:**

```text
MJQXGZJTGIQGS4ZAON2XAZLSEBRW63LNN5XCA2LOEBBVIRRHOM======
```

* Only contains `A-Z` and `2-7` → classic Base32.

**Python solution:**

```python
import base64

encoded = "MJQXGZJTGIQGS4ZAON2XAZLSEBRW63LNN5XCA2LOEBBVIRRHOM"
while len(encoded) % 8 != 0:
    encoded += '='
decoded = base64.b32decode(encoded)
print(decoded)
```

**✅ Result:**

```text
base32 is super common in CTF's
```

**File used:** `crackbase32.py`

---

## 4️⃣ Base64

**Challenge:**

```text
RWFjaCBCYXNlNjQgZGlnaXQgcmVwcmVzZW50cyBleGFjdGx5IDYgYml0cyBvZiBkYXRhLg==
```

**Solution:**

* Decode with any Base64 decoder: [Base64 Decoder](https://appdevtools.com/base64-encoder-decoder)

**✅ Result:**

```text
Each Base64 digit represents exactly 6 bits of data.
```

---

## 5️⃣ Hexadecimal

**Challenge:**

```text
68 65 78 61 64 65 63 69 6d 61 6c 20 6f 72 20 62 61 73 65 31 36 3f
```

**Solution:**

* Use CyberChef or hex converter: [CyberChef](https://gchq.github.io/CyberChef/)

**✅ Result:**

```text
hexadecimal or base16?
```

---

## 6️⃣ ROT13

**Challenge:**

```text
Ebgngr zr 13 cynprf!
```

**Solution:**

* Decode with ROT13: [ROT13 Decoder](https://cryptii.com/pipes/rot13-decoder)

**✅ Result:**

```text
Rotate me 13 places!
```

---

## 7️⃣ ROT47

**Challenge:**

```text
*@F DA:? >6 C:89E C@F?5 323J C:89E C@F?5 Wcf E:>6DX
```

**Solution:**

* Identify cipher: [dCode ROT47](https://www.dcode.fr/rot-47-cipher)

**✅ Result:**

```text
You spin me right round baby right round (47 times)
```

---

## 8️⃣ Morse Code

**Challenge:**

```text
- . .-.. . -.-. --- -- -- ..- -. .. -.-. .- - .. --- -.
. -. -.-. --- -.. .. -. --.
```

**Solution:**

* Decode: [Morse Code Decoder](https://www.dcode.fr/morse-code)

**✅ Result:**

```text
telecommunication encoding
```

---

## 9️⃣ Decimal ASCII

**Challenge:**

```text
85 110 112 97 99 107 32 116 104 105 115 32 66 67 68
```

**Solution:**

* Decode from decimal → ASCII: [CyberChef](https://gchq.github.io/CyberChef/)

**✅ Result:**

```text
Unpack this BCD
```

---

## 🔟 Combined Encoding

**Challenge:**

```text
LS0tLS0gLi0tLS0gLi0tLS0gLS0tLS0gLS0tLS0gLi0tLS0gLi0tLS0gLS0tLS0K...
```

**Solution Order:**

```
base64 → Morse code → ASCII → ROT47 → Decimal
```

* Copy everything, including `=` padding.
* Decode step by step.

---

## 🎵 Spectrograms

* Analyze audio with [Spectrum Analyzer](https://academo.org/demos/spectrum-analyzer/)
* Secret code found:

```
Super Secret Message
```

---

## 🗝 Steganography

* Use **Steghide** to extract hidden files:

```bash
steghide extract -sf stegosteg_1559008553457.jpg
```

* Extracted file: `steganopayload2248.txt`

**Content:**

```
SpaghettiSteg%
```

---

## 🔒 Security Through Obscurity

* Images may hide data in **metadata** or **appended files**.

**Example:**

```bash
binwalk -e meme_1559010886025.jpg
strings hackerchat.png
```

* Hidden flag:

```
AHH_YOU_FOUND_ME!
```

* Data appended at the end of PNG, not encrypted.

---

## 💡 Tips

* Use **strings**, **binwalk**, **stegsolve** for hidden data.
* Use **CyberChef**, **dCode**, and **Python** for decoding.
* Leet speak, Base32, Base64, Hex, ROT13/47, Morse, and BCD are all common in CTFs.

---

🎉 Happy CTF-ing! 🚀

