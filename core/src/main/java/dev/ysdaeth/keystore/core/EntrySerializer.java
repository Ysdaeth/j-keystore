package dev.ysdaeth.keystore.core;

import dev.ysdaeth.keystore.core.exception.KeyEntryFormatException;
import dev.ysdaeth.keystore.securer.api.SecuredEntry;
import dev.ysdaeth.keystore.securer.api.UnsecureEntry;

import java.security.PublicKey;
import java.util.*;

class EntrySerializer {
    private static final String BEGIN_PUBLIC = "-----BEGIN PUBLIC KEY-----";
    private static final String END_PUBLIC = "-----END PUBLIC KEY-----";
    private static final char KEY_VALUE_SEPARATOR = ':';
    private static final char PARAM_SEPARATOR = '|';


    /**
     * Serialize to DER PEM public key file format.
     * <pre>
     * {@code
     *     -----BEGIN PUBLIC KEY-----
     *      base64(key)
     *      -----END PUBLIC KEY-----
     * }
     * </pre>
     * @param publicKey key to serialize
     * @return serialized DER wrapped with PEM file
     */
    static String serialize(PublicKey publicKey){
        return publicKey.getAlgorithm() + '\n' +
                BEGIN_PUBLIC + '\n' +
                toBase64(publicKey.getEncoded()) +'\n' +
                END_PUBLIC;
    }

    /**
     * @param publicPEM DER PEM format public key
     * @return unsecured entry
     * @throws KeyEntryFormatException when format is not PEM
     */
    static UnsecureEntry deserializePublicKey(String publicPEM)
            throws KeyEntryFormatException {

        if(publicPEM == null ){
            throw new IllegalArgumentException("Serialized key must not be null");
        }

        String[] content = publicPEM.split("\n");

        int beginIndex = -1;
        for(int i=0; i<content.length; i++){
            if(!content[i].startsWith(BEGIN_PUBLIC)) continue;
            beginIndex = i;
            break;
        }
        if(beginIndex ==-1) throw new KeyEntryFormatException(
                "Serialized key is not public key ANS.1/DER format");

        String alg = content[beginIndex - 1];

        byte[] key = fromBase64(content[beginIndex + 1]);
        return new UnsecureEntry(key, alg);

    }

    static String serialize(SecuredEntry securedEntry){

        StringBuilder builder = new StringBuilder();

        String keyAlg = securedEntry.keyAlg();
        builder.append(keyAlg).append('\n');

        String mainKey = toBase64(securedEntry.key());
        builder.append(mainKey).append('\n');

        String securer = securedEntry.securer();
        builder.append(securer).append('\n');

        String kdf = securedEntry.kdf();
        builder.append(kdf).append('\n');

        String params = serializeMap(securedEntry.kdfParams());
        builder.append(params).append('\n');

        return builder.toString();
    }


    private static String serializeMap(Map<String,String> map){
        StringBuilder builder = new StringBuilder();
        for(var entry: map.entrySet()){
            String key = entry.getKey();
            String val = entry.getValue();
            builder.append(key).append(KEY_VALUE_SEPARATOR ).append(val).append(PARAM_SEPARATOR);
        }
        return builder.toString();
    }


    static SecuredEntry deserialize(String serializedEntry){
        String[] lines = serializedEntry.split("\n");

        return new SecuredEntry(
                lines[0], //alias
                fromBase64(lines[1]), // key
                lines[2], // securer
                lines[3], // kdf
                deserializeParametersMap(lines[4]) // kdf params
        );

    }

    private static Map<String,String> deserializeParametersMap(String serializedMap){
        List<String> entries = extractMapEntries(serializedMap);
        Map<String,String> resultMap = new HashMap<>(entries.size());

        for(String entry: entries){
            int separatorIndex = entry.indexOf(KEY_VALUE_SEPARATOR);
            String key = entry.substring(0, separatorIndex);
            String value = entry.substring(separatorIndex + 1);
            resultMap.put(key,value);
        }
        return resultMap;
    }

    private static List<String> extractMapEntries(String serializedMap){
        List<Integer> separatorIndexList = findCharacterIndexList(serializedMap, PARAM_SEPARATOR);
        List<String> entries = new ArrayList<>(separatorIndexList.size() + 1);

        int lastIndex = 0;
        for(int index: separatorIndexList){
            String entry = serializedMap.substring(lastIndex, index);
            entries.add(entry);
            lastIndex = index + 1;
        }
        return entries;
    }

    private static List<Integer> findCharacterIndexList(String str, char c){
        List<Integer> indexList = new ArrayList<>();
        for(int i =0; i< str.length(); i++){
            boolean equals = str.charAt(i) == c;
            if(equals) indexList.add(i);
        }
        return indexList;
    }

    private static String toBase64(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static byte[] fromBase64(String base64){
        return Base64.getDecoder().decode(base64);
    }

}
