package dev.ysdaeth.keystore.securer.api;

import java.util.Map;

public record SecuredEntry(String keyAlg,
                           byte[] key,
                           String securer,
                           String kdf,
                           Map<String,String> kdfParams){

}
