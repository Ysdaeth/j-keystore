package dev.ysdaeth.keystore.core;

import dev.ysdaeth.keystore.core.exception.EntryAlreadyExistsException;
import dev.ysdaeth.keystore.core.exception.IORuntimeException;
import dev.ysdaeth.keystore.core.exception.KeyEntryFormatException;
import dev.ysdaeth.keystore.core.exception.SecurerNotFoundException;
import dev.ysdaeth.keystore.deriver.api.KeyDeriverFactory;
import dev.ysdaeth.keystore.securer.api.*;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static dev.ysdaeth.keystore.core.EntryFileStore.*;

public class Keystore {

    private final EntryFileStore fileStore;
    private final List<EntrySecurerFactory> entrySecurerFactories;

    /**
     * Init keystore with custom list of factories
     * @param keyStorePath where to save files
     * @param secFactories factories
     */
    public Keystore(Path keyStorePath, List<EntrySecurerFactory> secFactories) throws IORuntimeException {

        try{
            Files.createDirectories(keyStorePath);
        }catch (IOException e){
            throw new IORuntimeException(e.getMessage(),e);
        }

        this.entrySecurerFactories = secFactories;
        this.fileStore = new EntryFileStore(keyStorePath);
    }

    /**
     * init keystore, and set custom securers.
     * @param keyStorePath where to save files
     * @param entrySecurerFactories custom securers.
     */
    public Keystore(Path keyStorePath, EntrySecurerFactory entrySecurerFactories) throws IORuntimeException {
        this(keyStorePath, List.of(entrySecurerFactories));
    }

    /**
     * Init keystore with default key derivers and entry securers
     */
    public Keystore(Path keyStorePath) throws IORuntimeException {
        KeyDeriverFactory kdfFactory = new DefaultKeyDeriverFactory();
        DefaultSecurerFactory securerFactory = new DefaultSecurerFactory(kdfFactory);
        this(keyStorePath, securerFactory);
    }

    public void save(PublicKey publicKey, String alias)
            throws EntryAlreadyExistsException, IORuntimeException {

        throwIfExist(alias, SSK, SPB, PEM);

        String serialized = EntrySerializer.serialize(publicKey);
        saveSerialized(serialized, alias, EntryFileStore.PEM);
    }

    public void save(PublicKey publicKey, String alias, char[] password)
            throws EntryAlreadyExistsException, IORuntimeException {

        throwIfExist(alias, SSK, SPB, PEM);

        UnsecureEntry entry = new UnsecureEntry(publicKey);
        String serialized = encryptAndSerialize(entry,password);
        saveSerialized(serialized, alias, EntryFileStore.SPB);
    }

    public void save(PrivateKey privateKey, String alias, char[] password)
            throws IORuntimeException, EntryAlreadyExistsException {

        throwIfExist(alias, SSK, SPV);

        UnsecureEntry entry = new UnsecureEntry(privateKey);
        String serialized = encryptAndSerialize(entry, password);
        saveSerialized(serialized, alias, SPV);
    }

    public void save(KeyPair keyPair, String alias, char[] password)
            throws IORuntimeException, EntryAlreadyExistsException {

        save(keyPair.getPrivate(),alias, password);
        save(keyPair.getPublic(), alias);
    }

    public void save(SecretKey secretKey, String alias, char[] password)
            throws IORuntimeException, EntryAlreadyExistsException {

        throwIfExist(alias, SSK, SPV, SPB, PEM);

        UnsecureEntry entry = new UnsecureEntry(secretKey);
        String serialized = encryptAndSerialize(entry,password);
        saveSerialized(serialized, alias, SSK);
    }

    public void save(Key key, String alias, char[] password)
            throws IORuntimeException, EntryAlreadyExistsException {

        switch (key) {
            case SecretKey ssk -> save(ssk, alias, password);
            case PublicKey spb -> save(spb, alias, password);
            case PrivateKey spv -> save(spv, alias, password);
            case null -> throw new IllegalArgumentException("Key must not be null");
            default -> throw new IllegalArgumentException("Unsupported Key instance");
        }
    }

    private void saveSerialized(String serialized, String alias, String extension)
            throws IORuntimeException, EntryAlreadyExistsException {
        try{
            fileStore.saveContent(serialized, alias, extension);
        }
        catch (FileAlreadyExistsException e){
            throw new EntryAlreadyExistsException('\'' + alias + "' already exists in keystore");
        }
        catch (IOException e){
            String exMsg = "Failed to save entry '%s'. %s. "
                    .formatted(alias, e.getMessage());
            throw new IORuntimeException(exMsg, e);
        }
    }

    private String encryptAndSerialize(UnsecureEntry entry, char[] password)
            throws IORuntimeException, EntryAlreadyExistsException {

        SecuredEntry secured = secureEntry(entry, password);
        return EntrySerializer.serialize(secured);
    }

    private SecuredEntry secureEntry(UnsecureEntry entry, char[] password)
            throws IORuntimeException, EntryAlreadyExistsException {

        EntrySecurer securer = entrySecurerFactories.getFirst().findDefault();

        try{
            return securer.encrypt(entry, password);
        }catch (GeneralSecurityException e){
            throw new RuntimeException("Failed to encrypt entry");
        }
    }


    public Optional<PublicKey> findPublicKey(String alias)
            throws InvalidPasswordException, IORuntimeException, KeyEntryFormatException {

        String serialized = loadSerialized(alias, EntryFileStore.PEM);

        if(serialized == null){
            boolean securedExists = fileStore.entryExists(alias, EntryFileStore.SPB);
            if(securedExists){
                throw new InvalidPasswordException("Public key is encrypted, but password was not provided");
            }
            return Optional.empty();
        }

        UnsecureEntry entry = EntrySerializer.deserializePublicKey(serialized);

        return Optional.of(
                tryRegeneratePublic(entry)
        );
    }

    public Optional<PublicKey> findPublicKey(String alias, char[] password)
            throws InvalidPasswordException, IORuntimeException, KeyEntryFormatException {

        String serialized = loadSerialized(alias, EntryFileStore.SPB);

        if(serialized == null){
            serialized = loadSerialized(alias, EntryFileStore.PEM);
            if(serialized == null) return Optional.empty();
            var entry = EntrySerializer.deserializePublicKey(serialized);
            return Optional.of( tryRegeneratePublic(entry) );
        }

        SecuredEntry secured = EntrySerializer.deserialize(serialized);
        UnsecureEntry entry = decryptEntry(secured,password);

        return Optional.of( tryRegeneratePublic(entry) );
    }


    public Optional<KeyPair> findKeyPair(String alias, char[] password)
            throws InvalidPasswordException, IORuntimeException, KeyEntryFormatException {

        PrivateKey pv = findPrivateKey(alias, password).orElse(null);
        if(pv == null) return Optional.empty();

        PublicKey pb = findPublicKey(alias, password).orElse(null);
        if(pb == null) return Optional.empty();

        return Optional.of(
                new KeyPair(pb, pv)
        );

    }

    public Optional<PrivateKey> findPrivateKey(String alias, char[] password){
        UnsecureEntry entry = findAndDecrypt(alias, password, SPV);
        return Optional.ofNullable( tryRegeneratePrivate(entry) );
    }

    public Optional<SecretKey> findSecretKey(String alias, char[] password){
        UnsecureEntry entry = findAndDecrypt(alias, password, SSK);

        return Optional.ofNullable( regenerateSecret(entry) );
    }

    private UnsecureEntry findAndDecrypt(String alias, char[] pwd, String extension)
            throws InvalidPasswordException, SecurerNotFoundException {

        String serialized = loadSerialized(alias, extension);
        if(serialized == null) return null;
        SecuredEntry securedEntry = EntrySerializer.deserialize(serialized);
        return decryptEntry(securedEntry, pwd);
    }


    private static PublicKey tryRegeneratePublic(UnsecureEntry entry){
        if(entry == null) return null;
        try {
            return KeyRevitalizer.regeneratePublic(entry);
        } catch (GeneralSecurityException e){
            throw new RuntimeException("Failed to regenerate public key. "+ e.getMessage(), e);
        }
    }

    private static PrivateKey tryRegeneratePrivate(UnsecureEntry entry){
        if(entry == null) return null;
        try{
            return KeyRevitalizer.regeneratePrivate(entry);
        }catch (GeneralSecurityException e){
            throw new RuntimeException("Failed to regenerate public key. "+ e.getMessage(), e);
        }
    }

    private static SecretKey regenerateSecret(UnsecureEntry entry){
        if(entry == null) return null;
        return KeyRevitalizer.regenerateSecretKey(entry);
    }

    private String loadSerialized(String alias, String fileExtension) throws IORuntimeException {
        try {
            return fileStore.loadContent(alias, fileExtension);
        }catch (IOException e){
            throw new IORuntimeException("Failed to load entry. " +e.getMessage(),e );
        }
    }


    private UnsecureEntry decryptEntry(SecuredEntry securedEntry, char[] password)
            throws InvalidPasswordException, SecurerNotFoundException {

        List<EntrySecurer> securers = findAllEntrySecurers(securedEntry.securer());

        if(securers.isEmpty()){
            throw new SecurerNotFoundException("There is no registered securer for : "+ securedEntry.securer());
        }

        for(EntrySecurer securer: securers){
            try{
                return securer.decrypt(securedEntry, password);
            }catch (InvalidPasswordException e){

            }catch(GeneralSecurityException e){
                throw new RuntimeException("Failed key entry decryption." + e.getMessage(), e);
            }
        }

        throw new InvalidPasswordException("Incorrect password");
    }


    private List<EntrySecurer> findAllEntrySecurers(String securerName){
        return entrySecurerFactories.stream()
                .map(f->f.findSecurer(securerName))
                .filter(Objects::nonNull)
                .toList();
    }

    private void throwIfExist(String alias, String ...extensions)
            throws EntryAlreadyExistsException {

        for(String extension: extensions){
            boolean exists = fileStore.entryExists(alias, extension);
            if(exists)  throw new EntryAlreadyExistsException(
                    "Entry '%s' already exist in keystore".formatted(alias));
        }
    }
}
