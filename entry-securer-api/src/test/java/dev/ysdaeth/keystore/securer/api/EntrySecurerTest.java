package dev.ysdaeth.keystore.securer.api;

import dev.ysdaeth.keystore.deriver.api.KeyDeriver;
import dev.ysdaeth.keystore.deriver.api.KeyDeriverFactory;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.List;


class EntrySecurerTest {

    // --- Tests ---

    @Test
    void shouldConstructSuccessfullyWhenFactoriesAreValid() {
        SecretKey key = new SecretKeySpec(new byte[32],"KEY");

        KeyDeriver deriverA = new StubKeyDeriver("DERIVER-A", key, key);
        KeyDeriver deriverB = new StubKeyDeriver("DERIVER-B", key, key);

        KeyDeriverFactory factory1 = new StubKeyDeriverFactory(List.of(deriverA), deriverA);
        KeyDeriverFactory factory2 = new StubKeyDeriverFactory(List.of(deriverB), deriverB);

        Assertions.assertDoesNotThrow(
                () -> new StubEntrySecurer("SecurerA",List.of(factory1, factory2))
        );
    }

    @Test
    void shouldFailWhenAnyFactoryReturnsNullOnGetDefault() {
        SecretKey key = new SecretKeySpec(new byte[16],"key");

        KeyDeriver validDeriver = new StubKeyDeriver("DERIVER-A", key, key);
        KeyDeriver otherDeriver = new StubKeyDeriver("DERIVER-B", key, key);

        KeyDeriverFactory validFactory = new StubKeyDeriverFactory(List.of(validDeriver), validDeriver);
        KeyDeriverFactory nullDefaultFactory = new StubKeyDeriverFactory(List.of(otherDeriver), null);

        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new StubEntrySecurer("SECURER",List.of(validFactory, nullDefaultFactory))
        );

    }

    @Test
    void shouldFailWhenFactoriesContainDuplicatedKeyDeriverNames() {
        SecretKey key = new SecretKeySpec(new byte[12],"KEY");
        KeyDeriver deriver1 = new StubKeyDeriver("DUPLICATE-NAME",key,key);
        KeyDeriver deriver2 = new StubKeyDeriver("DUPLICATE-NAME",key, key);

        KeyDeriverFactory factory1 = new StubKeyDeriverFactory(List.of(deriver1), deriver1);
        KeyDeriverFactory factory2 = new StubKeyDeriverFactory(List.of(deriver2), deriver2);

        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new StubEntrySecurer("SECURER", List.of(factory1, factory2))
        );
    }
}
