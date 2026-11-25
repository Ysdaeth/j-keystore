# How to use

## Add the dependency
First lets add the dependency
```xml
<dependency>
    <groupId>dev.ysdaeth.keystore</groupId>
    <artifactId>j-keystore</artifactId>
    <version>x.y.z</version>
</dependency>
```

---
## Create the key store
Make sure that Keystore is from the `dev.ysdaeth.keystore package`, Java KeyStore has similar name.  
Keystore will create a directory in the specified `keyStorePath`.
In the directory `keyStoreName` will be placed encrypted keys.

### All default
Creates instance with default key derivers and encryption algorithm
PBKDF2 for key derivation and AES-GCM for encryption.
Path is argument where keystore will be created.
```java
KeyStore keyStore = new KeyStore(Path keyStorePath);
```

### All default
Creates instance with default key derivers and custom encryption algorithm factory.
PBKDF2 for key derivation and AES-GCM for encryption.
Path is argument where keystore will be created, EntrySecurerFactory is factory that will provide EntrySecurer(s).
```java
KeyStore keyStore = new KeyStore(Path keyStorePath, EntrySecurerFactory factory);
```

### All default
Creates instance with custom key derivers and encryption algorithm factory.
Path is argument where keystore will be created, EntrySecurerFactory is factory that will provide EntrySecurer(s).
It supports multiple entry securer factories
```java
KeyStore keystore = new KeyStore(Path keyStorePath, List<EntrySecurerFactory> factoryList);
```

---

## Store the key
Keystore supports storing encrypted: Key, SecretKey, PrivateKey, PublicKey. 
It is also possible to store PublicKey not encrypted as a DER PEM format.
There can be key alias duplicates for asymmetric keys,
that means there can be saved "alias-name" alias for PrivateKey and it 
is possible to save PublicKey later

### Encrypt and store
SecretKey is used as an example, but it works also for Key, PrivateKey and PublicKey
```java
SecretKey keyToStore = // generate key.
String alias = "key-alias"; 
char[] password = "password".toCharArray(); // password that will be used to encrypt the key

keystore.save(keyToStore, alias, password);
```

### Store plain PublicKey
It is possible to store PublicKey in DER PEM file format.
```java
PublicKey publicKey = // generate public key
String alias = "pub-key"
keystore.save(publicKey, alias);
```

> [!TIP]
> Each unsecuredEntry is encrypted with a different random key to give you more time for the password rotation when key store leaks,
> but leaking the keystore and password may be catastrophic. Remember that you can use
> different passwords for each keystore entry


---

## Find stored key
When the key is already stored, it is possible to load it from the keystore as Optional.
If password is incorrect, then exception is thrown.

### Find encrypted public key 
When public key was not encrypted, the password will be sipped and public key returned
```java
keystore.findPublicKey(alias, password);
```

### Find public key
When key was encryped, then invalid password exception will be thrown.
```java
keystore.findPublicKey(alias);
```

### Find private key
```java
keystore.findPrivateKey(alias, password)
```

### Find key pair
```java
keystore.findKeyPair(alias, password)
```
