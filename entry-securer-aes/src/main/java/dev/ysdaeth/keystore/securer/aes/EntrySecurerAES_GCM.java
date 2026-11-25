package dev.ysdaeth.keystore.securer.aes;

import dev.ysdaeth.keystore.deriver.api.*;
import dev.ysdaeth.keystore.securer.api.InvalidPasswordException;
import dev.ysdaeth.keystore.securer.api.EntrySecurer;
import dev.ysdaeth.keystore.securer.api.SecuredEntry;
import dev.ysdaeth.keystore.securer.api.UnsecureEntry;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.List;

public class EntrySecurerAES_GCM extends EntrySecurer {
    private static final SecureRandom secureRandom = new SecureRandom();

    private final static String SECURER_NAME = "SECURER_AES-GCM";

    public EntrySecurerAES_GCM(List<KeyDeriverFactory> keyDeriverFactoryList){
        super(keyDeriverFactoryList);
    }

    public EntrySecurerAES_GCM(KeyDeriverFactory keyDeriverFactory){
        super(keyDeriverFactory);
    }

    public SecuredEntry encrypt(UnsecureEntry unsecureEntry, char[] password)
            throws GeneralSecurityException {

        KeyDeriver keyDeriver = defaultKeyDeriver();
        DerivedKey passwordKey = keyDeriver.generateKey(password,"AES");

        byte[] storedKey = encrypt(unsecureEntry.getKey(), passwordKey.secretKey());

        return new SecuredEntry(
                unsecureEntry.algorithm(),
                storedKey,
                SECURER_NAME,
                keyDeriver.getName(),
                passwordKey.params().map()
        );
    }

    @Override
    public UnsecureEntry decrypt(SecuredEntry securedEntry, char[] password)
            throws InvalidPasswordException, GeneralSecurityException, KeyDeriverNotFoundException {

        String kdf = securedEntry.kdf();
        KeyDeriver keyDeriver = findKeyDeriver(kdf);
        if(keyDeriver == null) {
            throw new KeyDeriverNotFoundException("There is no such key deriver: " + kdf);
        }

        KeyDeriverParams kdfParams = new KeyDeriverParams( securedEntry.kdfParams() );
        SecretKey passwordKey = keyDeriver.regenerateKey(password, kdfParams);

        byte[] storedKey = decrypt(securedEntry.key(), passwordKey);

        return new UnsecureEntry(
                storedKey, securedEntry.keyAlg()
        );
    }

    @Override
    public String getName() {
        return SECURER_NAME;
    }

    private static byte[] encrypt(byte[] rawData, SecretKey key)
            throws GeneralSecurityException {

        if(rawData == null) return null;

        byte[] iv = randomBytes(12);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);

        int outputLength = 1 + spec.getIV().length + cipher.getOutputSize(rawData.length);
        byte[] output = new byte[outputLength];
        output[0] = (byte) spec.getIV().length;
        System.arraycopy(iv, 0, output, 1, iv.length);

        cipher.doFinal(
                rawData,
                0, rawData.length,
                output,
                1 + iv.length
        );
        return output;
    }

    private static byte[] decrypt(byte[] encrypted, SecretKey secretKey)
            throws AEADBadTagException, GeneralSecurityException {

        if(encrypted == null) return null;
        byte ivLen = encrypted[0];
        byte[] iv = new byte[ivLen];
        System.arraycopy(encrypted,1,iv,0,ivLen);
        GCMParameterSpec spec = new GCMParameterSpec(128,iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,secretKey,spec);

        return cipher.doFinal(
                encrypted,
                1+ ivLen,
                encrypted.length - iv.length -1
        );
    }

    private static byte[] randomBytes(int length){
        byte[] bytes = new byte[length];
        secureRandom.nextBytes(bytes);
        return bytes;
    }

}
