# Custom Key Derivation & Encryption

The library separates cryptography into two independent API modules so you can plug in custom algorithms or migrate between algorithms seamlessly:

1. **`key-deriver-api`** – Turns a password into a cryptographic key (`KeyDeriver` & `KeyDeriverFactory`).
2. **`entry-securer-api`** – Encrypts and decrypts keystore entries (`EntrySecurer` & `EntrySecurerFactory`).

---

## 1. Implementing a Custom Key Deriver (`key-deriver-api`)

### Implement `KeyDeriver`
A `KeyDeriver` handles generating a fresh key (with a new random salt/parameters) during encryption and regenerating that exact key during decryption.

```java
public class Argon2KeyDeriver implements KeyDeriver {

    @Override
    public String getName() {
        // Must be unique across all registered KeyDerivers
        return "ARGON2ID";
    }

    @Override
    public DerivedKey generateKey(char[] password, String keyAlgorithm) throws GeneralSecurityException {
        // 1. Generate a random salt and derive key bytes from the password
        // 2. Wrap into a SecretKey for `keyAlgorithm` (e.g., "AES")
        // 3. Return DerivedKey containing the SecretKey and KeyDeriverParams (salt, iterations, etc.)
    }

    @Override
    public SecretKey regenerateKey(char[] password, KeyDeriverParams params) throws GeneralSecurityException {
        // Re-derive the exact same SecretKey using the stored params (salt, iterations, etc.)
    }
}
```

### Extend `KeyDeriverFactory`
`KeyDeriverFactory` manages one or more `KeyDeriver` instances and defines which one is used by default for new keys.

```java
public class CustomKeyDeriverFactory extends KeyDeriverFactory {

    private final KeyDeriver defaultDeriver;

    public CustomKeyDeriverFactory(List<KeyDeriver> derivers, KeyDeriver defaultDeriver) {
        super(derivers); // Validates that all deriver names are non-null, non-blank, and unique
        this.defaultDeriver = defaultDeriver;
    }

    @Override
    public KeyDeriver getDefault() {
        return defaultDeriver; // Must never return null
    }
}
```

---

## 2. Implementing a Custom Entry Securer (`entry-securer-api`)

### Extend `EntrySecurer`
`EntrySecurer` handles the actual encryption and decryption of entry bytes. Extending `EntrySecurer` gives you two built-in helper methods:
* `defaultKeyDeriver()` – Returns the default `KeyDeriver` (from the first `KeyDeriverFactory` passed to the constructor) to use when encrypting.
* `findKeyDeriver(String id)` – Searches all registered `KeyDeriverFactory` instances by deriver name to locate the right algorithm during decryption.

```java
public class ChaCha20EntrySecurer extends EntrySecurer {

    public ChaCha20EntrySecurer(KeyDeriverFactory factory) {
        super(factory);
    }

    public ChaCha20EntrySecurer(List<KeyDeriverFactory> factories) {
        super(factories); // Validates that there are no duplicate KeyDeriver names across factories
    }

    @Override
    public String getName() {
        // Must be unique across all registered EntrySecurers
        return "CHACHA20-POLY1305";
    }

    @Override
    public SecuredEntry encrypt(UnsecureEntry unsecureEntry, char[] password)
            throws InvalidPasswordException, GeneralSecurityException, KeyDeriverNotFoundException {

        KeyDeriver deriver = defaultKeyDeriver();
        DerivedKey derived = deriver.generateKey(password, "ChaCha20");

        // Encrypt unsecureEntry using derived.secretKey()
        // Store this securer's name, deriver.getName(), derived.params(), and ciphertext in SecuredEntry
    }

    @Override
    public UnsecureEntry decrypt(SecuredEntry securedEntry, char[] password)
            throws InvalidPasswordException, GeneralSecurityException {

        KeyDeriver deriver = findKeyDeriver(securedEntry.deriverName());
        if (deriver == null) {
            throw new KeyDeriverNotFoundException("Missing deriver: " + securedEntry.deriverName());
        }

        SecretKey key = deriver.regenerateKey(password, securedEntry.deriverParams());
        // Decrypt securedEntry and return UnsecureEntry
    }
}
```

### Extend `EntrySecurerFactory`
`EntrySecurerFactory` groups your `EntrySecurer` implementations and specifies which one is used for new entries.

```java
public class CustomEntrySecurerFactory extends EntrySecurerFactory {

    private final EntrySecurer defaultSecurer;

    public CustomEntrySecurerFactory(List<EntrySecurer> securers, EntrySecurer defaultSecurer) {
        super(securers); // Validates that securer names are unique and the list is non-empty
        this.defaultSecurer = defaultSecurer;
    }

    @Override
    public EntrySecurer findDefault() {
        return defaultSecurer; // Must never return null
    }
}
```

---

## 3. Wiring Everything Into `Keystore`

Once your factories are implemented, pass them to `Keystore` on initialization:

```java
KeyDeriver argon2 = new Argon2KeyDeriver();
KeyDeriverFactory kdfFactory = new CustomKeyDeriverFactory(List.of(argon2), argon2);

EntrySecurer chaChaSecurer = new ChaCha20EntrySecurer(kdfFactory);
EntrySecurerFactory securerFactory = new CustomEntrySecurerFactory(List.of(chaChaSecurer), chaChaSecurer);

Keystore keystore = new Keystore(Path.of("/path/to/keystore"), securerFactory);
```

### Important Contract Rules
* **Unique Names:** Every `KeyDeriver` and `EntrySecurer` must return a unique, non-blank string from `getName()`. These names are persisted in the keystore entry metadata so the library knows which algorithm to select during decryption.
* **Algorithm Rotation:** To migrate from an old algorithm to a new one, pass both old and new implementations into your factories, and set the **new** one as the default (`getDefault()` / `findDefault()`). Existing keys will still decrypt with the old implementation, while newly saved keys will use the new default.
