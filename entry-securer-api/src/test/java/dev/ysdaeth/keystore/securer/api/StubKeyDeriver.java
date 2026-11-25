package dev.ysdaeth.keystore.securer.api;

import dev.ysdaeth.keystore.deriver.api.DerivedKey;
import dev.ysdaeth.keystore.deriver.api.KeyDeriver;
import dev.ysdaeth.keystore.deriver.api.KeyDeriverParams;

import javax.crypto.SecretKey;
import java.util.Map;

public class StubKeyDeriver implements KeyDeriver {
    private final String name;
    private final SecretKey generatedKey;
    private final SecretKey regeneratedKey;

    public StubKeyDeriver(String name, SecretKey generatedKey, SecretKey regeneratedKey) {
        this.name = name;
        this.generatedKey = generatedKey;
        this.regeneratedKey = regeneratedKey;
    }

    @Override
    public DerivedKey generateKey(char[] password, String keyAlgorithm) {
        return new DerivedKey(generatedKey, new KeyDeriverParams(Map.of())) ;
    }

    @Override
    public SecretKey regenerateKey(char[] password, KeyDeriverParams params) {
        return regeneratedKey;
    }

    @Override
    public String getName() {
        return name;
    }
}
