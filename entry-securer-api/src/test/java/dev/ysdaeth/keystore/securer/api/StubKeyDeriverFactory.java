package dev.ysdaeth.keystore.securer.api;

import dev.ysdaeth.keystore.deriver.api.KeyDeriver;
import dev.ysdaeth.keystore.deriver.api.KeyDeriverFactory;

import java.util.List;

public class StubKeyDeriverFactory extends KeyDeriverFactory {

    private final KeyDeriver defaultDeriver;

    StubKeyDeriverFactory(List<KeyDeriver> keyDerivers, KeyDeriver defaultDeriver) {
        super(keyDerivers);
        this.defaultDeriver = defaultDeriver;
    }

    @Override
    public KeyDeriver getDefault() {
        return defaultDeriver;
    }
}
