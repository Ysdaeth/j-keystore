package dev.ysdaeth.keystore.core;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;

class EntryFileStore {

    private final Path keystorePath;

    public EntryFileStore(Path keystorePath) {
        this.keystorePath = keystorePath;
    }

    public static final String SSK = ".key";
    public static final String PEM = ".pem";
    public static final String SPV = ".pv";
    public static final String SPB = ".pb";

    String loadContent(String filename, String extension)
            throws IOException {

        boolean exists = entryExists(filename,extension);
        if(!exists) return null;
        String fullName = filename + extension;
        File securedEntryFile = getFile(keystorePath, fullName);
        if(!securedEntryFile.isFile()) return null;

        return Files.readString(securedEntryFile.toPath());
    }

    void saveContent(String content, String filename, String extension)
            throws IOException, FileAlreadyExistsException {

        String fullName = filename + extension;
        File securedEntryFile = getFile(keystorePath, fullName);
        if(securedEntryFile.isFile()) throw new FileAlreadyExistsException(filename);
        Files.writeString(securedEntryFile.toPath(), content);
    }

    private static File getFile(Path storePath, String filename){
        Path filePath = Path.of(storePath.toString(), filename);
        return filePath.toFile();
    }

    boolean entryExists(String filename, String fileExtension){
        String fullName = filename + fileExtension;
        File file = getFile(keystorePath, fullName);
        return file.exists();
    }

}
