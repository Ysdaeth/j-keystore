package dev.ysdaeth.keystore.securer.api;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public abstract class EntrySecurerFactory {

    private Map<String,EntrySecurer> securerMap;

    public EntrySecurerFactory(List<EntrySecurer> securers){
        validateSecurers(securers);
        this.securerMap = securers.stream()
                .collect(
                        Collectors.toMap(EntrySecurer::getName, s->s)
                );
    }

    public final EntrySecurer findSecurer(String name){
        return securerMap.get(name);
    }

    public abstract EntrySecurer findDefault();

    private static void validateSecurers(List<EntrySecurer> securers)
            throws IllegalStateException {

        ifNullEx(securers,"Securer list must not be null");
        if(securers.isEmpty()) argEx("Factory list must not be empty");

        Set<String> names = new HashSet<>();
        for(EntrySecurer securer: securers){
            String name =securer.getName();
            if(names.contains(name)) argEx("Entry securers has duplicated name: "+ name);
            names.add(name);
        }
    }

    private static void argEx(String message) throws IllegalStateException{
        throw new IllegalArgumentException(message);
    }

    private static void ifNullEx(Object o, String msg)
            throws IllegalArgumentException {
        if(o == null) argEx(msg);
    }
}
