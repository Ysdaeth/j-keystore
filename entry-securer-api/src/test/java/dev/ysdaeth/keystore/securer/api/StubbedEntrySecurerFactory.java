package dev.ysdaeth.keystore.securer.api;

import java.util.List;

public class StubbedEntrySecurerFactory extends EntrySecurerFactory {
    private final EntrySecurer ds;
    public StubbedEntrySecurerFactory(List<EntrySecurer> securers, EntrySecurer defaultSecurer) {
        super(securers);
        this.ds = defaultSecurer;
    }

    @Override
    public EntrySecurer findDefault() {
        return ds;
    }
}
