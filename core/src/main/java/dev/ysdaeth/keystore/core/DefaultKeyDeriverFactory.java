package dev.ysdaeth.keystore.core;

import dev.ysdaeth.keystore.deriver.api.KeyDeriver;
import dev.ysdaeth.keystore.deriver.api.KeyDeriverFactory;
import dev.ysdaeth.keystore.pbkdf.KeyDeriverPBKDF2;

import java.util.List;

public class DefaultKeyDeriverFactory extends KeyDeriverFactory {
    private static final KeyDeriver pbkdfDeriver = new KeyDeriverPBKDF2();

    public DefaultKeyDeriverFactory() {
        super( List.of(pbkdfDeriver) );
    }

    @Override
    public KeyDeriver getDefault() {
        return pbkdfDeriver;
    }
}
