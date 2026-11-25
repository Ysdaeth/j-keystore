package dev.ysdaeth.keystore.securer.api;

import dev.ysdaeth.keystore.deriver.api.KeyDeriver;
import dev.ysdaeth.keystore.deriver.api.KeyDeriverFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.util.List;

public class EntrySecurerFactoryTest {

    @Test
    void shouldThrowWhenContainsSecurersWithTheSameNames(){
        KeyDeriver kdf1 = new StubKeyDeriver("TEST-NAME1",null,null);

        KeyDeriverFactory kdfF1 = new StubKeyDeriverFactory(List.of(kdf1), kdf1);

        EntrySecurer securer1 = new StubEntrySecurer("DUPLICATED-NAME",List.of(kdfF1));
        EntrySecurer securer2 = new StubEntrySecurer("DUPLICATED-NAME",List.of(kdfF1));

        Assertions.assertThrows( IllegalArgumentException.class, ()-> {
            new StubbedEntrySecurerFactory(List.of(securer1, securer2), securer1);
        });

    }

    @Test
    void shouldNotThrowOnValidConstructorArgs(){
        KeyDeriver kdf1 = new StubKeyDeriver("TEST-NAME1",null,null);

        KeyDeriverFactory kdfF1 = new StubKeyDeriverFactory(List.of(kdf1), kdf1);

        EntrySecurer securer1 = new StubEntrySecurer("UNIQUE-NAME-1",List.of(kdfF1));
        EntrySecurer securer2 = new StubEntrySecurer("UNIQUE-NAME-2",List.of(kdfF1));

        Assertions.assertDoesNotThrow( ()-> {
            new StubbedEntrySecurerFactory(List.of(securer1, securer2), securer1);
        });

    }
}
