package dev.ysdaeth.keystore.securer.api;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class UnsecureEntry {
    private final String keyAlgorithm;
    private final byte[] key;
    boolean destroyed = false;

    public UnsecureEntry(SecretKey key) {
        this(
                key.getEncoded(),
                key.getAlgorithm()
        );
    }

    public UnsecureEntry(PrivateKey privateKey){
        this(
                privateKey.getEncoded(),
                privateKey.getAlgorithm()
        );
    }

    public UnsecureEntry(PublicKey publicKey){
        this(
                publicKey.getEncoded(),
                publicKey.getAlgorithm()
        );
    }

    public UnsecureEntry(byte[] key, String keyAlgorithm){
        this.key = key.clone();
        this.keyAlgorithm = keyAlgorithm;
    }

    public byte[] getKey(){
        return key;
    }

    public String algorithm(){
        return keyAlgorithm;
    }

    public void destroy() {
        if(destroyed) return;
        if (key != null) Arrays.fill(key, (byte) 0);
        destroyed = true;
    }
}
