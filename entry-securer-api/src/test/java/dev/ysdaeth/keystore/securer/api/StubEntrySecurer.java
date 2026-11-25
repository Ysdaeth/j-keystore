package dev.ysdaeth.keystore.securer.api;

import dev.ysdaeth.keystore.deriver.api.KeyDeriverFactory;

import java.util.List;

public class StubEntrySecurer extends EntrySecurer {

    final String name;

    public StubEntrySecurer(String name, List<KeyDeriverFactory> factories) {
        super(factories);
        this.name = name;
    }

    @Override
    public SecuredEntry encrypt(UnsecureEntry unsecureEntry, char[] password) {return null;}

    @Override
    public UnsecureEntry decrypt(SecuredEntry securedEntry, char[] password){return null;}

    @Override
    public String getName() {return name;}
}
