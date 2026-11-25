package dev.ysdaeth.keystore.securer.api;

import dev.ysdaeth.keystore.deriver.api.KeyDeriver;
import dev.ysdaeth.keystore.deriver.api.KeyDeriverFactory;
import dev.ysdaeth.keystore.deriver.api.KeyDeriverNotFoundException;

import java.security.GeneralSecurityException;
import java.util.*;

public abstract class EntrySecurer {

    private final List<KeyDeriverFactory> keyDeriverFactories;

    public EntrySecurer(KeyDeriverFactory keyDeriverFactories) throws IllegalArgumentException {
        this( List.of(keyDeriverFactories) );
    }

    public EntrySecurer(List<KeyDeriverFactory> keyDeriverFactories) throws IllegalArgumentException {
        validateDerivers(keyDeriverFactories);
        this.keyDeriverFactories = keyDeriverFactories;
    }

    public abstract SecuredEntry encrypt(UnsecureEntry unsecureEntry, char[] password)
            throws InvalidPasswordException, GeneralSecurityException, KeyDeriverNotFoundException;

    public abstract UnsecureEntry decrypt(SecuredEntry securedEntry, char[] password)
            throws InvalidPasswordException, GeneralSecurityException;

    protected final KeyDeriver findKeyDeriver(String id) {
        for(KeyDeriverFactory factory: keyDeriverFactories){
            KeyDeriver deriver = factory.getInstance(id);
            if(deriver != null) return deriver;
        }
        return null;
    }

    protected final KeyDeriver defaultKeyDeriver() {
        return keyDeriverFactories.getFirst().getDefault();
    }

    public abstract String getName();


    private static void validateDerivers(List<KeyDeriverFactory> factories)
            throws IllegalArgumentException {

        ifNullEx(factories,"List of key deriver factories must not be null");
        if(factories.isEmpty()) argEx("List of key deriver factories must not be empty");

        Set<String> seen = new HashSet<>();
        Set<String> duplicates = new HashSet<>();

        for (KeyDeriverFactory factory : factories) {
            for (String name : factory.allKeyDeriverNames()) {
                if (!seen.add(name)) duplicates.add(name);
            }
        }

        if (!duplicates.isEmpty()) {
            String names = String.join(", ", duplicates);
            argEx("Key deriver factories has duplicated key derivers: "+ names);
        }

        for(KeyDeriverFactory factory: factories){
            ifNullEx(factory.getDefault(),
                    "factory '%s' returned null as default KeyDeriver"
                            .formatted(factory.getClass())
            );
        }
    }

    private static void argEx(String msgEx) throws IllegalArgumentException {
        throw new IllegalArgumentException(msgEx);
    }

    private static void ifNullEx(Object o, String msgEx) throws IllegalArgumentException {
        if(o == null) argEx(msgEx);
    }
}
