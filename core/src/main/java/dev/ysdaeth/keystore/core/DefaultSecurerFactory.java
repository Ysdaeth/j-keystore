package dev.ysdaeth.keystore.core;

import dev.ysdaeth.keystore.deriver.api.KeyDeriverFactory;
import dev.ysdaeth.keystore.securer.aes.EntrySecurerAES_GCM;
import dev.ysdaeth.keystore.securer.api.EntrySecurer;
import dev.ysdaeth.keystore.securer.api.EntrySecurerFactory;

import java.util.List;

class DefaultSecurerFactory extends EntrySecurerFactory {

    private final EntrySecurer defaultSecurer;

    private DefaultSecurerFactory(List<KeyDeriverFactory> deriverFactories) {
        EntrySecurer aesSecurer = new EntrySecurerAES_GCM(deriverFactories);
        super(List.of(aesSecurer));
        this.defaultSecurer = aesSecurer;
    }

    DefaultSecurerFactory(KeyDeriverFactory deriverFactories){
        this(List.of(deriverFactories));
    }


    @Override
    public EntrySecurer findDefault() {
        return defaultSecurer;
    }

}
