package dev.ysdaeth.keystore.core;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Random;
import java.util.function.Supplier;
import java.util.stream.Stream;

public class KeystoreTest {

    static final Path testDir = Path.of("src", "test", "resources", "temp", "keystoreTest");
    static final Keystore keystore = new Keystore(testDir);
    static final char[] password = "password".toCharArray();

    static int tests =0;
    static Supplier<String> generateAlias = ()->{
        tests++;
        return "test_"+ tests;
    };

    @BeforeAll
    static void setup() throws Exception {
        try(Stream<Path> pathStream = Files.walk(testDir)){
            pathStream.map(Path::toFile).forEach(File::delete);
        }
        Files.createDirectories(testDir);
    }


    @ParameterizedTest
    @MethodSource("secretKey_Alias_args")
    void save_shouldSaveAndReturn_secretKey(SecretKey secretKey, String alias) throws Exception {
        keystore.save(secretKey, alias, password);
        SecretKey actualKey = keystore.findSecretKey(alias, password).orElse(null);

        assertNotNull(actualKey);
        assertArrayEquals(secretKey.getEncoded(), actualKey.getEncoded());
    }

    @ParameterizedTest
    @MethodSource("keyPair_Alias_args")
    void save_shouldSaveAndReturn_keyPair(KeyPair pair, String alias) throws Exception {

        keystore.save(pair, alias, password);
        KeyPair actualPair = keystore.findKeyPair(alias, password).orElse(null);

        assertNotNull(actualPair);

        assertArrayEquals(pair.getPrivate().getEncoded(), actualPair.getPrivate().getEncoded());
        assertArrayEquals(pair.getPublic().getEncoded(), actualPair.getPublic().getEncoded());
    }


    public static Stream<Arguments> keyPair_Alias_args() {
        return TestUtils.generateKeyPairs().stream()
                .map(pair -> Arguments.of(pair, generateAlias.get()));
    }

    public static Stream<Arguments> secretKey_Alias_args() throws Exception{
        byte[] key = new byte[256];
        new Random().nextBytes(key);
        SecretKey customKey = new SecretKeySpec(key,"custom");
        return Stream.of(
                (Arguments) createArgs("AES", generateAlias.get()),
                createArgs("HmacSHA256", generateAlias.get()),
                createArgs("HmacSHA384", generateAlias.get()),
                createArgs("HmacSHA512", generateAlias.get()),
                createArgs("HmacSHA256", generateAlias.get()),
                Arguments.of(customKey,generateAlias.get())
        );
    }

    private static Arguments createArgs(String alg, String alias) throws Exception{
        return Arguments.of( KeyGenerator.getInstance(alg).generateKey(), alias);
    }
}
