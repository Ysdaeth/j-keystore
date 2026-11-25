package dev.ysdaeth.keystore.deriver.api;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class KeyDeriverFactory {

    private final Map<String,KeyDeriver> keyDerivers;

    public KeyDeriverFactory(List<KeyDeriver> keyDerivers) {

        validateDerivers(keyDerivers);
        this.keyDerivers = toMap(keyDerivers);
    }

    /**
     * Algorithm that is responsible for key derivation.
     * If there is no specified algorithm it can return null.
     * @param deriverName key deriver name to find
     * @return instance of the key entry securer or NULL
     */
    public KeyDeriver getInstance(String deriverName){
        return keyDerivers.get(deriverName);
    }

    public Set<String> allKeyDeriverNames(){
        return keyDerivers.keySet();
    }

    /**
     * Always returns current entry securer to secure keys.
     * @return entry securer to encrypt key entry, NEVER null
     */
    public abstract KeyDeriver getDefault();

    private void validateDerivers(List<KeyDeriver> derivers) throws IllegalArgumentException {

        Set<String> nameSet = new HashSet<>();
        for(KeyDeriver deriver: derivers){
            String name = deriver.getName();
            ifNullEx(name,"Key deriver has null name" + deriver.getClass() );
            if(name.isBlank()){
                argEx("Key deriver name is blank" + deriver.getClass());
            }

            if(nameSet.contains(name)) argEx("Key deriver have duplicated names: "+ name);
            nameSet.add(name);
        }
    }

    private static void argEx(String msg) throws IllegalArgumentException {
        throw new IllegalArgumentException(msg);
    }

    private static void ifNullEx(Object o, String msg)
            throws IllegalArgumentException {
        if(o == null) argEx(msg);
    }

    private static Map<String, KeyDeriver> toMap(List<KeyDeriver> derivers){
        return derivers.stream()
                .collect(
                        Collectors.toMap(KeyDeriver::getName, d->d)
                );
    }
}
