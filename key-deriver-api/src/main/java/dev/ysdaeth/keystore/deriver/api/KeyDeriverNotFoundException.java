package dev.ysdaeth.keystore.deriver.api;

public class KeyDeriverNotFoundException extends RuntimeException {
    public KeyDeriverNotFoundException(String message) {
        super(message);
    }
}
