package dev.ysdaeth.keystore.core;

import java.security.*;
import java.util.*;

public class TestUtils {

    static List<KeyPair> generateKeyPairs(){
        Map<String, String> algorithms = new LinkedHashMap<>();

        for (Provider provider : Security.getProviders()) {
            for (Provider.Service service : provider.getServices()) {

                if (service.getType().equalsIgnoreCase("KeyPairGenerator")) {
                    String algorithm = service.getAlgorithm();

                    algorithms.putIfAbsent(
                            algorithm.toUpperCase(Locale.ROOT),
                            algorithm
                    );
                }
            }
        }

        List<KeyPair> pairs = new ArrayList<>();

        for (String algorithm : algorithms.values()) {

            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
                KeyPair keyPair = generator.generateKeyPair();
                pairs.add(keyPair);
            } catch (GeneralSecurityException | RuntimeException e) {
                System.err.println("Could not generate " + algorithm + ": " + e.getMessage());
            }
        }
        return pairs;

    }
}
