# Simple Key Store

## Store and retrieve cryptographic keys in the easy way

### Focus on managing your keys, not how to retrieve them.
Standard `java.security.KeyStore` requires verbose setup, streams, and casting just to read or write a key pair. 
**Simpler Key Store** eliminates that boilerplate with a clean, straightforward API.

### One key, one password
Each stored entry can be encrypted with its own password.  
By default, keys are derived using PBKDF2 with HmacSHA256 and encrypted with AES-GCM.

### One key, one file
Keys are stored as separate files in a directory rather than bundled into monolithic file. This simplifies integration with file access loggers, intrusion detection systems, decoy files, and granular OS-level permissions.

### Highly customizable
Unlike `java.security.KeyStore`, this library lets you create your own key derivation and encryption logic.  
It supports multiple key derivation functions and encryptors at once.

---  


> [!WARNING]
> Supported key pair encodings are **X.509** for public keys and **PKCS#8** for private keys.

## Documentation
- [How to install](docs/Installation.md) 
- [How to use](docs/HowToUse.md)

## Requirements
* Java 25
