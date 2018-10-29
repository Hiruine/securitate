package com.crypt;

import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Paths;

class EncryptorTest {

    @Test
    void canEncrypt() throws IOException, URISyntaxException {
        String inputMessage = "Encrypt";
        String password = "password";
        KeyGenerator keyGenerator = new KeyGenerator(password);

        Encryptor encryptor = new Encryptor(inputMessage, keyGenerator);
        String encryptedMessage = encryptor.encrypt();
        System.out.println(encryptedMessage);

        Decryptor decryptor = new Decryptor(encryptedMessage, keyGenerator);
        String decryptedMessage = decryptor.decrypt();
        System.out.println(decryptedMessage);


    }
}