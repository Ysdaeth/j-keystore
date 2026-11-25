package dev.ysdaeth.keystore.pbkdf;

import dev.ysdaeth.keystore.deriver.api.DerivedKey;
import dev.ysdaeth.keystore.deriver.api.KeyDeriver;
import dev.ysdaeth.keystore.deriver.api.KeyDeriverParams;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;
import java.util.function.Function;


public class KeyDeriverPBKDF2 implements KeyDeriver {
    private static final String SECURER_NAME = "PBKDF2";

    private String KDF = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 600_000;
    private static final int KEY_LENGTH = 256;

    private static final String SALT_PARAM ="s";
    private static final String ITER_PARAM = "it";
    private static final String KEY_SIZE_PARAM = "ks";
    private static final String KEY_ALG_PARAM = "ka";


    @Override
    public DerivedKey generateKey(char[] password, String keyAlgorithm) throws GeneralSecurityException {
        byte[] salt = randomBytes(16);
        SecretKey secretKey = deriveKey(password, salt, ITERATIONS, KEY_LENGTH, keyAlgorithm);
        KeyDeriverParams params = buildParams(salt, ITERATIONS, KEY_LENGTH, keyAlgorithm);
        return new DerivedKey(secretKey, params);
    }

    @Override
    public SecretKey regenerateKey(char[] password, KeyDeriverParams params) throws GeneralSecurityException {
        byte[] salt = extractParam(SALT_PARAM, params, Base64.getDecoder()::decode);
        int iterations = extractParam(ITER_PARAM, params, Integer::parseInt);
        int keyLen = extractParam(KEY_SIZE_PARAM, params, Integer::parseInt);
        String keyAlg = extractParam(KEY_ALG_PARAM, params, s->s);
        return deriveKey(password, salt, iterations, keyLen,keyAlg);
    }

    private SecretKey deriveKey(char[] pwd, byte[] salt,int iterations,int keyLen, String keyAlg)
            throws GeneralSecurityException {

        KeySpec spec = new PBEKeySpec(pwd, salt, iterations, keyLen);
        byte[] key = SecretKeyFactory.getInstance(KDF).generateSecret(spec).getEncoded();
        return new SecretKeySpec(key, keyAlg);
    }


    private static KeyDeriverParams buildParams(byte[] salt, int iterations, int keySize, String keyAlg){
        Map<String,String> params = new HashMap<>();
        params.put(SALT_PARAM, Base64.getEncoder().encodeToString(salt) );
        params.put(ITER_PARAM, Objects.toString(iterations) );
        params.put(KEY_SIZE_PARAM, Objects.toString(keySize) );
        params.put(KEY_ALG_PARAM, keyAlg );
        return new KeyDeriverParams(params);
    }

    private static <T> T extractParam(String paramName, KeyDeriverParams params, Function<String,T> callback) {
        String paramValue = params.map().get(paramName);
        return callback.apply(paramValue);
    }

    @Override
    public String getName() {
        return SECURER_NAME;
    }

    private static byte[] randomBytes(int length){
        byte[] bytes = new byte[length];
        new SecureRandom().nextBytes(bytes);
        return bytes;
    }

}