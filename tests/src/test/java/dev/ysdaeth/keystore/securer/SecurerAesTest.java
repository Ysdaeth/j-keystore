package dev.ysdaeth.keystore.securer;

import dev.ysdaeth.keystore.core.DefaultKeyDeriverFactory;
import dev.ysdaeth.keystore.deriver.api.KeyDeriverFactory;
import dev.ysdaeth.keystore.securer.aes.EntrySecurerAES_GCM;
import dev.ysdaeth.keystore.securer.api.EntrySecurer;
import static org.junit.jupiter.api.Assertions.*;

import dev.ysdaeth.keystore.securer.api.SecuredEntry;
import dev.ysdaeth.keystore.securer.api.UnsecureEntry;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.Arrays;
import java.util.stream.Stream;

public class SecurerAesTest {

    private final char[] PASSWORD = "password".toCharArray();

    private final KeyDeriverFactory factory = new DefaultKeyDeriverFactory();
    private EntrySecurerAES_GCM securerAESGcm = new EntrySecurerAES_GCM(factory);

    @ParameterizedTest
    @MethodSource("entrySecurers")
    void getName_shouldReturnNonNullName(EntrySecurer securer){
        String name = securer.getName();
        assertNotNull(name);
    }

    @ParameterizedTest
    @MethodSource("entrySecurers")
    void encrypt_shouldNotReturnRawBytes(EntrySecurer securer) throws Exception {

        byte[] secret = new byte[]{1,2,3,4,5,6,7,8};
        UnsecureEntry unsecureEntry = new UnsecureEntry(secret.clone(),"algorithm");

        SecuredEntry securedEntry = securer.encrypt(unsecureEntry, PASSWORD);
        byte[] encrypted = securedEntry.key();

        boolean arrayEquals = Arrays.equals(secret, encrypted);
        assertFalse(arrayEquals,"Secret is not encrypted");
    }

    @ParameterizedTest
    @MethodSource("entrySecurers")
    void encrypt_shouldBeReversible(EntrySecurer securer) throws Exception {

        byte[] secret = new byte[]{1,2,3,4,5,6,7,8};
        UnsecureEntry unsecureEntry = new UnsecureEntry(secret.clone(),"algorithm");

        SecuredEntry securedEntry = securer.encrypt(unsecureEntry, PASSWORD);

        UnsecureEntry decrypted = securer.decrypt(securedEntry,PASSWORD);

        assertArrayEquals(secret.clone(), decrypted.getKey());

    }

    static Stream<EntrySecurer> entrySecurers(){
        KeyDeriverFactory keyDeriverFactory = new DefaultKeyDeriverFactory();
        return Stream.of(
                new EntrySecurerAES_GCM(keyDeriverFactory)
        );
    }


}
