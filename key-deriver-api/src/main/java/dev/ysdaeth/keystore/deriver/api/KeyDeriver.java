package dev.ysdaeth.keystore.deriver.api;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

public interface KeyDeriver {
    DerivedKey generateKey(char[] password, String keyAlgorithm) throws GeneralSecurityException;
    SecretKey regenerateKey(char[] password, KeyDeriverParams params) throws GeneralSecurityException;
    String getName();

}
