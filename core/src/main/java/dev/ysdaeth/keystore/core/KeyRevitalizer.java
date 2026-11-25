package dev.ysdaeth.keystore.core;


import dev.ysdaeth.keystore.securer.api.UnsecureEntry;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

class KeyRevitalizer {

    static PublicKey regeneratePublic(UnsecureEntry entry)
            throws GeneralSecurityException {

        X509EncodedKeySpec spec = new X509EncodedKeySpec(entry.getKey());
        KeyFactory keyFactory = KeyFactory.getInstance(entry.algorithm());
        return keyFactory.generatePublic(spec);
    }

    static PrivateKey regeneratePrivate(UnsecureEntry entry)
            throws GeneralSecurityException {
        var spec = new PKCS8EncodedKeySpec(entry.getKey());
        KeyFactory keyFactory = KeyFactory.getInstance(entry.algorithm());
        return keyFactory.generatePrivate(spec);
    }

    static SecretKey regenerateSecretKey(UnsecureEntry entry){
        return new SecretKeySpec(entry.getKey(),entry.algorithm());
    }

}
