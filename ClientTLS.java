import java.io.*;
import java.net.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.security.*;

public class ClientTLS {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 12345;
    static String nonceString;
    private static String target;
    private static String targetKey;
    private static boolean loggedIn;
    private static Map<String, String> usersKeys = new HashMap<>();


    public static void main(String[] args) {
        String clientID = args.length > 0 ? args[0] : "client1";
        try {
            char[] password = "password".toCharArray();
            KeyStore keyStore = KeyStore.getInstance("JKS");
            KeyStore trustStore = KeyStore.getInstance("JKS");

            keyStore.load(new FileInputStream(clientID + ".jks"), password);
            trustStore.load(new FileInputStream("client-truststore.jks"), password);

            TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
            tmf.init(trustStore);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, password);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());

            SSLSocketFactory sslSocketFactory = sslContext.getSocketFactory();

            SSLSocket socket = (SSLSocket) sslSocketFactory.createSocket(SERVER_HOST, SERVER_PORT);
               
            // enable all the cipher suites
            String[] supported = socket.getSupportedCipherSuites();
            socket.setEnabledCipherSuites(supported);

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(
                    socket.getOutputStream(), true);

            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));

            Key key = keyStore.getKey(clientID, password);
            if (!(key instanceof PrivateKey)) throw new Exception("Not a private key");

            PrivateKey privateKey = (PrivateKey) key;
            Certificate cert = keyStore.getCertificate(clientID);
            PublicKey publicKey = cert.getPublicKey();
            String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());

            

            new Thread(() -> {
                try {
                    String response;
                    while ((response = in.readLine()) != null) {
                        System.out.println(response);
                        if (response.startsWith("Nonce|")) {
                            nonceString = response;
                            String[] nonceParts = nonceString.split("\\|", 2);
                            nonceString = nonceParts[1];
                            System.out.println(nonceString);
                            byte[] nonce = Base64.getDecoder().decode(nonceString);

                            Signature sig = Signature.getInstance("SHA256withRSA");
                            sig.initSign(privateKey);
                            sig.update(nonce);

                            byte[] signature = sig.sign();
                            String signatureStr = Base64.getEncoder().encodeToString(signature);

                            System.out.println("Sending decrypted nonce");
                            out.println(signatureStr);
                            continue;
                        }

                        if (response.startsWith("key|")) {
                            String[] parts = response.split("\\|");
                            String keyOwner = parts[1];
                            String keyStr = parts[2];

                            System.out.println("Received key for " + keyOwner);

                            usersKeys.put(keyOwner, keyStr);
                            continue;
                        }

                        if (response.equals("Authentication successful.")) {
                            loggedIn = true;
                            continue;
                        }

                        if (response.startsWith("New target")) {
                            continue;
                        }

                        if (response.startsWith("msg")) {
                            String[] responseParts = response.split("\\|");

                            if (responseParts.length < 2)  {
                                continue;
                            }
                            String author = responseParts[1];
                            //String target = responseParts[2];
                            String encryptedAESKey = responseParts[2];
                            String encryptedMessage = responseParts[3];

                            System.out.println("Encrypted String: " + encryptedMessage);

                            byte[] encryptedAESBytes = Base64.getDecoder().decode(encryptedAESKey);

                            Cipher cipher = Cipher.getInstance("RSA");
                            cipher.init(Cipher.DECRYPT_MODE, privateKey);

                            byte[] decryptedAESBytes = cipher.doFinal(encryptedAESBytes);
                            SecretKey aesKey = new SecretKeySpec(decryptedAESBytes, "AES");


                            byte[] encryptedMessageBytes = Base64.getDecoder().decode(encryptedMessage);

                            Cipher aesCipher = Cipher.getInstance("AES");
                            aesCipher.init(Cipher.DECRYPT_MODE, aesKey);

                            byte[] decrypted = aesCipher.doFinal(encryptedMessageBytes);
                            String plaintext = new String(decrypted);

                            System.out.println(author + ": " + plaintext);
                        }

                        
                        
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
                catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();

            String fullMessage;
            while ((fullMessage = userInput.readLine()) != null) {
                if (loggedIn) {
                    if (fullMessage.contains("target|")) {
                        String[] parts = fullMessage.split("\\|", 2);
                        if (parts.length < 2)  {
                            out.println("Invalid message format. Use target|<user>");
                            continue;
                        }
                        target = parts[1];

                        if (target != null && !usersKeys.containsKey(target)) {
                            out.println("getKey|" + target);
                        }

                        out.println(fullMessage);
                        continue;
                    }

                    if (target != null) {
                        if (usersKeys.containsKey(target)) {
                            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                            keyGen.init(128);
                            SecretKey aesKey = keyGen.generateKey();

                            Cipher aesCipher = Cipher.getInstance("AES");
                            aesCipher.init(Cipher.ENCRYPT_MODE, aesKey);

                            byte[] encryptedMessage = aesCipher.doFinal(fullMessage.getBytes());
                            String encryptedMessageStr = Base64.getEncoder().encodeToString(encryptedMessage);

                            String targetPublicKeyString = usersKeys.get(target);

                            byte[] keyBytes = Base64.getDecoder().decode(targetPublicKeyString);
                            KeyFactory kf = KeyFactory.getInstance("RSA");
                            PublicKey targetPublicKey = kf.generatePublic(new X509EncodedKeySpec(keyBytes));

                            Cipher rsaCipher = Cipher.getInstance("RSA");
                            rsaCipher.init(Cipher.ENCRYPT_MODE, targetPublicKey);

                            byte[] encryptedKey = rsaCipher.doFinal(aesKey.getEncoded());
                            String encryptedKeyStr = Base64.getEncoder().encodeToString(encryptedKey);

                            out.println("msg|" + target + "|" + encryptedKeyStr + "|" + encryptedMessageStr);
                        } else {
                            System.out.println("Can't find target public key, sending request to server. Send your message again soon.");
                            out.println("getKey|" + target);
                        }

                        //out.println(fullMessage);
                    } else {
                        System.out.println("Can't send a message without a target, use target|<user>");
                    }
                } else {
                    if (fullMessage.equals("key")) {
                        fullMessage = publicKeyStr;
                        out.println(fullMessage);
                        continue;
                    }
                    out.println(fullMessage);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}