# Section 1.4 - Cryptographic Solutions
**Date:** November 23, 2025  
**Source:** Professor Messer Security+ SY0-701  
**Section:** General Security Concepts

---

## Public Key Infrastructure (PKI)

### What is PKI?

**Components of PKI:**
- Policies
- Procedures
- Hardware
- Software
- People

**Primary Function:**
- Digital certificates: **create, distribute, manage, store, revoke**

**Important Note:**
- This is a **big, big endeavor**
- Lots of planning required

**Also Refers To:**
- The binding of public keys to people and devices
- Managed by the **Certificate Authority (CA)**
- **It's all about TRUST**

---

## Symmetric Encryption

### How It Works:

**Single Key System:**
- A single, shared key
- Encrypt with the key
- Decrypt with the **same key**
- If it gets out, you'll need another key

**Also Called:**
- Secret Key algorithm
- A shared secret

### Characteristics:

**Disadvantages:**
- ❌ Doesn't scale very well
- ❌ Can be challenging to distribute securely

**Advantages:**
- ✅ **Very fast to use**
- ✅ Less overhead than asymmetric encryption
- ✅ Often combined with asymmetric encryption

### Key Concept:
**ONE KEY for both encryption and decryption**

---

## Asymmetric Encryption

### What is Asymmetric Encryption?

**Also Known As:**
- Public key cryptography

**Key Characteristics:**
- Two or more **mathematically related keys**

**The Two Keys:**

1. **Private Key:**
   - Keep this one **PRIVATE**
   - Only you have this

2. **Public Key:**
   - Anyone can see this key
   - **Give it away** freely

### Critical Rule:

**The private key is the ONLY key that can decrypt data encrypted with the public key**

**Important:** You **cannot** derive the private key from the public key

---

## The Key Pair

### Key Generation Process:

**Asymmetric Encryption Setup:**
- Public key cryptography
- **Build both the public and private key at the same time**

**How Keys Are Generated:**
- Lots of randomization
- Large prime numbers
- Lots and lots of math

### Distribution:

**Public Key:**
- ✅ **EVERYONE** can have the public key
- Freely distributed

**Private Key:**
- 🔒 **ONLY ALICE** has the PRIVATE key
- Never shared
- Must be protected

---

## Asymmetric Encryption in Action

### Step-by-Step Process:

**Step 1: Bob Creates a Message**
- Bob has a message to send to Alice
- Bob has Alice's **public key**

**Step 2: Encryption**
- Bob uses Alice's **public key** to encrypt the message
- The key creates a **cipher text**
- Only Alice can unlock it with her **private key**

**Step 3: Alice Receives the Message**
- Alice receives the cipher text
- Alice uses her **private key** to unlock the cipher

**Step 4: Decryption Complete**
- Alice has decrypted the encrypted message sent by Bob
- Message is now readable

### Key Concept:
**Encrypt with PUBLIC key → Decrypt with PRIVATE key**

---

## Key Escrow

### What is Key Escrow?

**Definition:**
- Someone else holds your decryption keys
- Your **private keys** are in the hands of a 3rd party
- This may be within your own organization

### Legitimate Use Cases:

**Business Reasons:**
- A business might need access to employee information
- Example: Employee leaves, company needs to decrypt their files

**Government Reasons:**
- Government agencies may need to decrypt partner data
- Law enforcement access to encrypted communications

### Controversy:

**Is It Controversial?**
- ⚠️ **Of course!**
- Privacy concerns
- Security risks (3rd party has your keys)

**Reality:**
- May still be **required** by policy or law
- Trade-off between security and access

---

## Key Takeaways for Exam:

### Symmetric vs Asymmetric Comparison:

| Feature | Symmetric | Asymmetric |
|---------|-----------|------------|
| **Keys** | 1 shared key | 2 keys (public + private) |
| **Speed** | ⚡ Fast | 🐢 Slower |
| **Key Distribution** | ❌ Difficult | ✅ Easy (public key) |
| **Scalability** | ❌ Poor | ✅ Excellent |
| **Use Case** | Bulk encryption | Key exchange, digital signatures |
| **Examples** | AES, DES, 3DES | RSA, ECC, Diffie-Hellman |

### PKI Components to Remember:

✅ **Certificate Authority (CA)** - Issues and manages certificates  
✅ **Public Key** - Shared freely, used to encrypt  
✅ **Private Key** - Kept secret, used to decrypt  
✅ **Digital Certificates** - Bind public keys to identities  
✅ **Trust Model** - Chain of trust from root CA  

### Encryption Rules:

🔐 **Symmetric:** Same key encrypts AND decrypts  
🔐 **Asymmetric:** Public key encrypts, private key decrypts  
🔐 **Hybrid Approach:** Use asymmetric to exchange symmetric key, then use symmetric for speed  

---

## Common Exam Questions:

**Q: What encrypts data that only the private key can decrypt?**  
**A:** The public key

**Q: What's the main advantage of symmetric encryption?**  
**A:** Speed (much faster than asymmetric)

**Q: What's the main advantage of asymmetric encryption?**  
**A:** Key distribution (public key can be shared freely)

**Q: Who holds keys in key escrow?**  
**A:** A trusted 3rd party (could be internal or external)

**Q: Can you derive the private key from the public key?**  
**A:** NO - mathematically related but cannot be reversed

---

## Related Concepts:

- Certificate Authority (CA)
- Root CA vs Intermediate CA
- Chain of Trust
- Digital Signatures
- Hybrid Encryption
- Key Exchange protocols

---

## Encrypting Data

### Protecting Data at Rest

**Data at Rest:**
- Protect data on storage devices
- SSD, hard drive, USB drive, cloud storage, etc.
- Data that is stored (not moving)

**Full-Disk and Partition/Volume Encryption:**
- **BitLocker** (Windows)
- **FileVault** (macOS)
- Encrypts entire drive or partition

**File Encryption:**
- **EFS (Encrypting File System)** - Windows
- Third-party utilities
- Encrypts individual files or folders

---

### Database Encryption

**Purpose:**
- Protecting stored data
- AND the transmission of that data

**Transparent Encryption:**
- Encrypt ALL database information with a symmetric key
- Application doesn't need to know about encryption
- Transparent to the end user

**Record-Level Encryption:**
- Encrypt individual columns
- Use separate symmetric keys for each column
- More granular control
- Different keys for different data types

---

### Transport Encryption

**Purpose:**
- Protect data traversing the network
- You're probably doing this now (HTTPS)

**Encrypting in the Application:**
- Browsers can communicate using **HTTPS**
- Application-layer encryption
- SSL/TLS protocols

**VPN (Virtual Private Network):**
- Encrypts ALL data transmitted over the network
- **Client-based VPN** - Uses SSL/TLS
- **Site-to-Site VPN** - Uses IPsec
- Creates encrypted tunnel

---

## Encryption Algorithms

### How Algorithms Work

**Many Different Ways to Encrypt Data:**
- The proper "formula" must be used during encryption AND decryption
- Both sides decide on algorithm before encrypting the data
- The details are often hidden from the end user

**Advantages and Disadvantages:**
- Security level
- Speed
- Complexity
- Implementation considerations

---

## Cryptographic Keys

### The Key is Everything

**What Is Known:**
- There's very little that isn't known about the cryptographic process
- The algorithm is usually a known entity
- **The ONLY thing you don't know is the KEY**

**The Key Determines the Output:**
- Encrypted data
- Hash value
- Digital signature

**Critical Rule:**
- 🔒 **KEEP YOUR KEY PRIVATE!**
- It's the ONLY thing protecting your data

---

### Key Lengths

**Why Larger Keys Are Better:**
- Larger keys tend to be more secure
- Prevent brute force attacks
- Attackers can try every possible key combination

**Symmetric Encryption:**
- **128-bit or larger** symmetric keys are common
- These numbers get larger and larger as time goes on
- Example: AES-128, AES-256

**Asymmetric Encryption:**
- Complex calculations of prime numbers
- **Larger keys than symmetric encryption**
- Common to see key lengths of **3,072 bits or longer**
- Example: RSA-2048, RSA-4096

---

### Key Stretching

**Problem:**
- A weak key is a weak key
- By itself, it's not very secure

**Solution - Key Stretching:**
- Make a weak key stronger by performing multiple processes
- **Hash a password → Hash the hash → Hash again → Continue**
- Also called: **Key strengthening**

**Benefit:**
- Brute force attacks would require reversing each of those hashes
- The attacker has to spend MUCH more time
- Even though the original key is small

**Examples:**
- PBKDF2 (Password-Based Key Derivation Function 2)
- Bcrypt
- Scrypt

---

## Key Exchange

### The Logistical Challenge

**Problem:**
- How do you share an encryption key across an insecure medium?
- Can't physically transfer key every time
- Network is insecure

---

### Out-of-Band Key Exchange

**Don't Send the Symmetric Key Over the Network:**
- Telephone
- Courier (physical delivery)
- In-person meeting
- USB drive hand delivery

**Pros:** Very secure  
**Cons:** Not scalable, slow, inconvenient

---

### In-Band Key Exchange

**It's On the Network:**
- Protect the key with additional encryption
- **Use asymmetric encryption to deliver a symmetric key**

**This is the modern solution!**

---

### Real-Time Encryption/Decryption

**The Need:**
- There's a need for fast security
- Without compromising the security part

**Solution - Session Keys:**

**How It Works:**
1. **Share symmetric session key using asymmetric encryption**
2. Client encrypts random (symmetric) key with server's public key
3. Server decrypts this shared key
4. Uses it to encrypt data
5. This is the **session key**

**Implementation Requirements:**
- Keys need to be changed often (**ephemeral keys**)
- Keys need to be unpredictable (random)

---

### Symmetric Key from Asymmetric Keys

**Use Public and Private Key Cryptography to Create a Symmetric Key:**
- Math is powerful!

**Step-by-Step Process:**

```
Step 1: Alice creates symmetric key
   [Symmetric Key: "abc123"]

Step 2: Alice encrypts it with Bob's public key
   Bob's Public Key → [Encrypted: "xj#9k2@"]

Step 3: Sent over network (safe even if intercepted!)
   Network → [Encrypted: "xj#9k2@"]

Step 4: Bob decrypts with his private key
   Bob's Private Key → [Symmetric Key: "abc123"]

Step 5: Both have same symmetric key, use for communication
   Alice ←→ [Fast AES encryption] ←→ Bob
```

**This is Hybrid Encryption!**
- Asymmetric for key exchange (secure)
- Symmetric for data transfer (fast)

---

## Encryption Technologies

### Trusted Platform Module (TPM)

**What is TPM?**
- A specification for cryptographic functions
- **Cryptography hardware on a device**
- Built into the motherboard

**Components:**

**Cryptographic Processor:**
- Random number generator
- Key generator

**Persistent Memory:**
- Unique keys burned in during manufacturing
- Cannot be changed

**Versatile Memory:**
- Storage for keys
- Hardware configuration information
- **Securely store BitLocker keys**

**Security Features:**
- Password protected
- No dictionary attacks possible
- Hardware-based encryption

---

### Hardware Security Module (HSM)

**What is HSM?**
- Used in large environments
- Enterprise-level cryptographic hardware

**Features:**
- Clusters, redundant power
- **Securely store thousands of cryptographic keys**

**High-End Cryptographic Hardware:**
- Plug-in card OR separate hardware device
- Much more powerful than TPM

**Capabilities:**
- **Key backup** - Secure storage in hardware
- **Cryptographic accelerators** - Offload CPU overhead from other devices
- High-speed encryption/decryption

**Use Cases:**
- Banks, financial institutions
- Data centers
- Large-scale PKI deployments

---

### Key Management System (KMS)

**The Challenge:**
- Services are everywhere
- On-premises, cloud-based
- Many different keys for many different services

**Solution - Centralized Management:**
- **All key management from one console**

**Capabilities:**

1. **Create Keys:**
   - For specific service or cloud provider
   - SSL/TLS, SSH, etc.

2. **Associate Keys:**
   - Link keys with specific users
   - Control who can use which keys

3. **Rotate Keys:**
   - On regular intervals
   - Automated key rotation

4. **Logging:**
   - Log key use
   - Track important events
   - Audit trail

**Features:**
- Dashboard of key management system
- View all keys and associated servers
- SSH console communication details
- Reports and analytics
  - How keys are being used
  - How often keys are being used
  - Compliance reporting

---

### Keeping Data Private

**The Challenge:**
- Our data is located in different places (mobile phones, laptops, etc.)
- The most private data is often physically closest to us
- Attackers are always finding new techniques
- It's a race to stay one step ahead
- Our data is changing constantly
- How do we keep this data protected?

---

### Secure Enclave

**What is a Secure Enclave?**
- A protected area for our secrets
- Often implemented as a **hardware processor**
- **Isolated from the main processor**
- Many different technologies and names

**Examples:**
- Apple Secure Enclave (iPhone, Mac)
- ARM TrustZone
- Intel SGX (Software Guard Extensions)

**Security Features:**

✅ **Has its own boot ROM**  
✅ **Monitors the system boot process**  
✅ **True random number generator**  
✅ **Real-time memory encryption**  
✅ **Root cryptographic keys**  
✅ **Performs AES encryption in hardware**  

**Use Cases:**
- Biometric data storage (fingerprints, Face ID)
- Payment credentials (Apple Pay, Google Pay)
- Password management
- Cryptographic key storage

---

## Key Takeaways for Exam:

### Data Protection Types:
| Type | Examples | Purpose |
|------|----------|---------|
| **Data at Rest** | BitLocker, FileVault, EFS | Encrypt stored data |
| **Data in Transit** | HTTPS, VPN, TLS | Encrypt network traffic |
| **Data in Use** | Secure Enclave | Encrypt active memory |

### Key Lengths to Remember:
- **Symmetric:** 128-bit or 256-bit (AES)
- **Asymmetric:** 2048-bit or 4096-bit (RSA)
- **Larger = More secure** (but slower)

### Key Exchange Methods:
- **Out-of-band:** Physical delivery (secure but not scalable)
- **In-band:** Asymmetric encryption (scalable and secure)

### Hardware Security:
- **TPM:** Built-in chip for device encryption (BitLocker)
- **HSM:** Enterprise hardware for thousands of keys
- **Secure Enclave:** Isolated processor for sensitive data

### Key Management:
- **Centralized KMS** for managing all keys
- **Key rotation** on regular intervals
- **Logging and auditing** for compliance

---

*Notes completed: November 23, 2025*  
*Status: Section 1.4 Part 1 - COMPLETE!* ✅  
*Next: Section 1.4 Part 2 (Obfuscation, Hashing, Blockchain, Certificates)*
