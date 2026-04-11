import java.io.*;
import java.nio.file.Files;
import java.util.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import javax.net.ssl.*;

public class ServerTLS {
    private static final int port = 12345;
    private static Map<String, PrintWriter> clients = new HashMap<>();
    private static Map<String, String> registeredUsers = new HashMap<>();

    private static final String FILE_NAME = "registeredUsers.dat";

    private static SecretKey aesKey;

    public static final String SHA_CRYPT = "SHA-256";
    public static final String AES_ALGORITHM = "AES";
    public static final String AES_ALGORITHM_GCM = "AES/GCM/NoPadding";

    public static final Integer IV_LENGTH_ENCRYPT = 12;
    public static final Integer TAG_LENGTH_ENCRYPT = 16;
    public static void main(String[] args) {
        System.out.println("Server started...");

        try {
            char[] password = "password".toCharArray();
            KeyStore keyStore = KeyStore.getInstance("JKS");
            KeyStore trustStore = KeyStore.getInstance("JKS");

            keyStore.load(new FileInputStream("server.jks"), password);
            trustStore.load(new FileInputStream("server-truststore.jks"), password);

            aesKey = loadOrCreateAESKey(keyStore, password);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(trustStore);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, password);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();

            SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port);

            serverSocket.setNeedClientAuth(false);

            // enable all the cipher suites
            String[] supported = serverSocket.getSupportedCipherSuites();
            serverSocket.setEnabledCipherSuites(supported);

            registeredUsers = loadUsersFromFile();

            while (true) {
                SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
                System.out.println("New client connected");

                new Thread(new ClientHandler(clientSocket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static Map<String, String> loadUsersFromFile() {
        File f = new File(FILE_NAME);

        if (!f.exists() || f.length() == 0) {
            System.out.println("No valid user file found, starting fresh.");
            return new HashMap<>();
        }

        try {
            byte[] encrypted = Files.readAllBytes(f.toPath());
            byte[] decrypted = localGCMDecrypt(encrypted);

            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decrypted));
            Object obj = ois.readObject();

            if (!(obj instanceof Map)) throw new IOException("Invalid data format: not a Map");

            Map<String, String> result = new HashMap<>();
            Map<?, ?> rawMap = (Map<?, ?>) obj;

            for (Map.Entry<?, ?> entry : rawMap.entrySet()) {
                if (!(entry.getKey() instanceof String) || !(entry.getValue() instanceof String)) throw new IOException("Invalid map contents");
                result.put((String) entry.getKey(), (String) entry.getValue());
            }

            return result;

        } catch (Exception e) {
            System.out.println("Tampering detected or corrupted file! Resetting users.");
            e.printStackTrace();
            return new HashMap<>();
        }
    }

    private static void saveUsersToFile() {
        try {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            ObjectOutputStream oos = new ObjectOutputStream(bos);
            oos.writeObject(registeredUsers);
            oos.flush();

            byte[] plainData = bos.toByteArray();

            byte[] encrypted = localGCMEncrypt(plainData);

            FileOutputStream fos = new FileOutputStream(FILE_NAME);
            fos.write(encrypted);
            fos.close();

            System.out.println("Users saved securely.");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // GCM encryption followed with the tutorial from https://medium.com/@johnvazna/implementing-local-aes-gcm-encryption-and-decryption-in-java-ac1dacaaa409

    public static byte[] localGCMEncrypt(byte[] plainBytes) throws Exception {
        // Generate a random IV
        byte[] iv = new byte[IV_LENGTH_ENCRYPT];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(iv);

        // Initialize cipher in AES-GCM mode
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM_GCM);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_ENCRYPT * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        // Encrypt the plainbytes
        byte[] encryptedBytes = cipher.doFinal(plainBytes);

        // Combine IV and encrypted text
        byte[] combinedIvAndCipherText = new byte[iv.length + encryptedBytes.length];
        System.arraycopy(iv, 0, combinedIvAndCipherText, 0, iv.length);
        System.arraycopy(encryptedBytes, 0, combinedIvAndCipherText, iv.length, encryptedBytes.length);

        return combinedIvAndCipherText;
    }

    public static byte[] localGCMDecrypt(byte[] decodedCipherText) throws Exception {
        // Extract IV and encrypted text
        byte[] iv = new byte[IV_LENGTH_ENCRYPT];
        System.arraycopy(decodedCipherText, 0, iv, 0, iv.length);
        byte[] encryptedText = new byte[decodedCipherText.length - IV_LENGTH_ENCRYPT];
        System.arraycopy(decodedCipherText, IV_LENGTH_ENCRYPT, encryptedText, 0, encryptedText.length);

        // Initialize cipher in AES-GCM mode
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LENGTH_ENCRYPT * 8, iv);
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM_GCM);
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        // Decrypt the ciphertext
        byte[] decryptedBytes = cipher.doFinal(encryptedText);

        return decryptedBytes;
    }

    private static SecretKey loadOrCreateAESKey(KeyStore keyStore, char[] password) throws Exception {
        String alias = "chat-aes-key";

        if (keyStore.containsAlias(alias)) {
            KeyStore.Entry entry = keyStore.getEntry(alias, new KeyStore.PasswordProtection(password));
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);

        SecretKey aesKey = keyGen.generateKey();

        KeyStore.SecretKeyEntry secretEntry = new KeyStore.SecretKeyEntry(aesKey);
        KeyStore.ProtectionParameter protection = new KeyStore.PasswordProtection(password);

        keyStore.setEntry(alias, secretEntry, protection);

        try (FileOutputStream fos = new FileOutputStream("server.jks")) {
            keyStore.store(fos, password);
        }
        return aesKey;
    }

    private static String getConversationFile(String user1, String user2) throws Exception {
        List<String> users = Arrays.asList(user1, user2);
        Collections.sort(users);

        String combined = users.get(0) + users.get(1);

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(combined.getBytes());
        md.update(aesKey.getEncoded());
        byte[] hash = md.digest();

        return Base64.getUrlEncoder().encodeToString(hash) + ".chat";
    }

    private static byte[] encrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    private static synchronized void saveMessage(String message) throws Exception {
        String[] parts = message.split("\\|");
        String sender = parts[1];
        String receiver = parts[2];
        String fileName = getConversationFile(sender, receiver);
        File file = new File(fileName);

        String existing = "";

        if (file.exists()) {
            byte[] encrypted = Files.readAllBytes(file.toPath());
            byte[] decrypted = decrypt(encrypted, aesKey);
            existing = new String(decrypted);
        }

        String newLine = message + "\n";
        String updated = existing + newLine;

        byte[] encrypted = encrypt(updated.getBytes(), aesKey);

        Files.write(file.toPath(), encrypted);
    }

    static class ClientHandler implements Runnable {
        private SSLSocket socket;
        private BufferedReader in;
        private PrintWriter out;
        private String username;
        private boolean impostor = false;
        private boolean login = false;
        private String target;

        public ClientHandler(SSLSocket socket) {
            this.socket = socket;
        }

        public void run() {
            try {
                in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
                out = new PrintWriter(socket.getOutputStream(), true);

                // Ask client for username
                out.println("Enter your username:");
                username = in.readLine();

                synchronized (clients) {
                    if (clients.containsKey(username)) {
                        out.println("Username already taken. Disconnecting.");
                        out.println("exit|");
                        impostor = true;
                        socket.close();
                        return;
                    }
                    clients.put(username, out);
                }

                System.out.println(registeredUsers.keySet());

                synchronized (registeredUsers) {
                    if (registeredUsers.containsKey(username)) {
                        login = true;
                    } else {
                        out.println("Welcome, send your public key so we can register you (Base64 encoded):");
                        String pubKeyStr = in.readLine();
                        System.out.println(pubKeyStr);

                        if (registeredUsers.containsValue(pubKeyStr)) {
                            out.println("This key is already in use");
                            out.println("exit|");
                            impostor = true;
                            socket.close();
                            return;
                        }

                        registeredUsers.put(username, pubKeyStr);
                        saveUsersToFile();
                        out.println("Authentication successful.");
                    }
                }

                if (login) {
                    out.println("Username is already registered. Send back signed nonce to prove it's you.");

                    SecureRandom random = new SecureRandom();
                    byte[] nonce = new byte[32];
                    random.nextBytes(nonce);

                    String nonceStr = Base64.getEncoder().encodeToString(nonce);
                    out.println("Nonce|" + nonceStr);

                    String signedNonceStr = in.readLine();
                    System.out.println(signedNonceStr);
                    byte[] signedNonce = Base64.getDecoder().decode(signedNonceStr);

                    String storedKeyStr = registeredUsers.get(username);
                    byte[] keyBytes = Base64.getDecoder().decode(storedKeyStr);

                    KeyFactory kf = KeyFactory.getInstance("RSA");
                    PublicKey publicKey = kf.generatePublic(new X509EncodedKeySpec(keyBytes));

                    Signature sig = Signature.getInstance("SHA256withRSA");
                    sig.initVerify(publicKey);
                    sig.update(nonce);

                    boolean valid = sig.verify(signedNonce);

                    if (!valid) {
                        out.println("Authentication failed.");
                        out.println("exit|");
                        socket.close();
                        return;
                    } else {
                        out.println("Authentication successful.");
                    }
                }

                System.out.println(username + " connected.");

                String fullMessage;
                while ((fullMessage = in.readLine()) != null) {
                    if (fullMessage.equals("key") || fullMessage.equals("nonce")) continue;
                    System.out.println("Received: " + fullMessage);
                    String message = fullMessage;

                    if (fullMessage.startsWith("history|")) {
                        String[] parts = fullMessage.split("\\|", 2);
                        if (parts.length < 2)  {
                            out.println("Invalid message format. Use history|<user>");
                            continue;
                        }

                        String fileName = getConversationFile(username, parts[1]);

                        File file = new File(fileName);

                        String existing = "";

                        if (file.exists()) {
                            byte[] encrypted = Files.readAllBytes(file.toPath());
                            if (encrypted.length % 16 != 0) {
                                System.out.println("Corrupted or non-encrypted file detected");
                                existing = "";
                            } else {
                                byte[] decrypted = decrypt(encrypted, aesKey);
                                existing = new String(decrypted);
                            }
                        } else {
                            out.println("Can't find history with that user");
                            continue;
                        }

                        String[] lines = existing.split("\n");
                        for (String line : lines) {
                            System.out.println("newLine" + line);
                            out.println(line);
                        }
                    }

                    if (fullMessage.contains("target|")) {
                        String[] parts = fullMessage.split("\\|", 2);
                        if (parts.length < 2)  {
                            out.println("Invalid message format. Use target|<user>");
                            continue;
                        }

                        target = parts[1];

                        synchronized (clients) {
                            PrintWriter writer = clients.get(target);
                            if (writer == null) {
                                out.println("User " + target + " not connected.");
                                target = null;
                                continue;
                            } 
                        }

                        out.println("New target: " + target + " and all messages will go to them now. To set new target write target|<user>");
                        System.out.println("New target: " + target);
                        continue;

                        
                    } else if (fullMessage.startsWith("getKey|")) {
                        String[] parts = fullMessage.split("\\|", 2);
                        
                        if (parts.length < 2 || parts[1] == null)  {
                            out.println("Invalid message format. Use getKey|<user>");
                            continue;
                        }

                        String targetUsername = parts[1];
                        String storedKeyStr;

                        synchronized (registeredUsers) {
                            if (registeredUsers.containsKey(targetUsername)) {
                                storedKeyStr = registeredUsers.get(targetUsername);
                                out.println("key|" +targetUsername + "|" + storedKeyStr);
                            } else {
                                out.println("No key stored for such user.");
                            }
                        }
                    } else if (target == null) {
                        out.println("No target is specified. Use target|<user>");
                        continue;
                    } 

                    

                    if (target !=  null) {
                        synchronized (clients) {
                            PrintWriter writer = clients.get(target);
                            if (writer != null) {
                                writer.println(message);
                                if (message.startsWith("msg|")) {
                                    saveMessage(message);
                                }
                            } else {
                                out.println("User " + target + " not connected.");
                                target = null;
                            }
                        }
                    }
                }
            } catch (IOException e) {
                System.out.println("Client disconnected");
            } 
            catch (Exception e) {
                e.printStackTrace();
            }finally {
                try {
                    socket.close();
                } catch (IOException e) {}
                
                if (!impostor) {
                    synchronized (clients) {
                        clients.remove(username);
                    }
                    System.out.println(username + " removed from active clients.");
                }
            }
        }
    }
}