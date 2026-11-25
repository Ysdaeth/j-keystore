# How to use

## Add the dependency
First, add the dependency to your `pom.xml`:
```xml
<dependency>
    <groupId>dev.ysdaeth.keystore</groupId>
    <artifactId>j-keystore</artifactId>
    <version>x.y.z</version>
</dependency>
```

---

## Create the keystore
> [!IMPORTANT]
> Make sure to import `dev.ysdaeth.keystore.Keystore`, not `java.security.KeyStore`.

`Keystore` creates a directory at the specified `keyStorePath` where all key files will be stored.

### Default configuration
Creates an instance using the default key derivation (PBKDF2) and encryption (AES-GCM) algorithms:
```java
Path keyStorePath = Path.of("/path/to/keystore");
Keystore keystore = new Keystore(keyStorePath);
```

### Custom encryptor factory
Creates an instance using a custom `EntrySecurerFactory` to provide your own encryption and key derivation logic:
```java
Path keyStorePath = Path.of("/path/to/keystore");
EntrySecurerFactory factory = new CustomSecurerFactory(new DefaultKeyDeriverFactory());
Keystore keystore = new Keystore(keyStorePath, factory);
```

### Multiple factories (Algorithm Migration)
Supports multiple `EntrySecurerFactory` implementations simultaneously. 
**The first factory in the list** is used to encrypt newly saved entries, 
while all provided factories can be used to decrypt existing ones:
```java
Path keyStorePath = Path.of("/path/to/keystore");
List<EntrySecurerFactory> factories = List.of(newNewerSecurerFactory, legacySecurerFactory);
Keystore keystore = new Keystore(keyStorePath, factories);
```

---

## Store a key
`Keystore` supports encrypting and storing `Key`, `SecretKey`, `PrivateKey`, `PublicKey`, and `KeyPair` instances. 
You can also store an unencrypted `PublicKey` in PEM format.

Asymmetric keys can share the same alias—for example, you can save a `PrivateKey` under `"alias-name"` and later save 
its corresponding `PublicKey` under the exact same `"alias-name"`.

### Encrypt and store a key
Works with `SecretKey`, `PrivateKey`, `PublicKey`, or a generic `Key`:
```java
SecretKey keyToStore = // generate key
String alias = "key-alias";
char[] password = "password".toCharArray();

keystore.save(keyToStore, alias, password);
```

### Store a KeyPair
Saves the `PrivateKey` encrypted with the password and the `PublicKey` as an unencrypted PEM file under the same alias:
```java
KeyPair keyPair = // generate key pair
String alias = "my-keypair";
char[] password = "password".toCharArray();

keystore.save(keyPair, alias, password);
```

### Store a plain PublicKey
You can store a `PublicKey` without encryption as a PEM file:
```java
PublicKey publicKey = // generate public key
String alias = "pub-key";

keystore.save(publicKey, alias);
```

> [!TIP]
> Each entry is encrypted with a unique random key/salt to buy you time for key rotation if 
> the keystore directory leaks. However, leaking both the keystore and the password compromises the key.

---

## Find a stored key
Stored keys are returned wrapped as an `Optional`. If an incorrect password is provided for an encrypted 
key, exception`InvalidPasswordException` is thrown.

### Find a secret key
```java
Optional<SecretKey> secretKey = keystore.findSecretKey(alias, password);
```

### Find a private key
```java
Optional<PrivateKey> privateKey = keystore.findPrivateKey(alias, password);
```

### Find an encrypted public key
If the public key was stored unencrypted, the password is skipped and the public key is returned:
```java
Optional<PublicKey> publicKey = keystore.findPublicKey(alias, password);
```

### Find an unencrypted public key
If the key was encrypted, calling this method without a password throws an `InvalidPasswordException`:
```java
Optional<PublicKey> publicKey = keystore.findPublicKey(alias);
```

### Find a key pair
```java
Optional<KeyPair> keyPair = keystore.findKeyPair(alias, password);
```

---
