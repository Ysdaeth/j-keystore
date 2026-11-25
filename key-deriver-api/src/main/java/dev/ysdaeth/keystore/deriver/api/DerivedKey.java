package dev.ysdaeth.keystore.deriver.api;

import javax.crypto.SecretKey;

public record DerivedKey(SecretKey secretKey, KeyDeriverParams params) {
}
