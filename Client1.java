import java.io.*;
import java.net.*;
import javax.net.ssl.*;
import java.security.cert.CertificateException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.security.*;

public class Client1 {
    private static final String SERVER_HOST = "localhost";
    private static final int SERVER_PORT = 12345;
    static String nonceString;

    public static void main(String[] args) {
        String username = args.length > 0 ? args[0] : "Anonymous";
        try {
            char[] password = "password".toCharArray();
            KeyStore keyStore = KeyStore.getInstance("JKS");
            KeyStore trustStore = KeyStore.getInstance("JKS");

            keyStore.load(new FileInputStream("client1.jks"), password);
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

            Key key = keyStore.getKey("client1", password);
            if (!(key instanceof PrivateKey)) throw new Exception("Not a private key");

            PrivateKey privateKey = (PrivateKey) key;
            Certificate cert = keyStore.getCertificate("client1");
            PublicKey publicKey = cert.getPublicKey();
            String publicKeyStr = Base64.getEncoder().encodeToString(publicKey.getEncoded());

            

            new Thread(() -> {
                try {
                    String response;
                    while ((response = in.readLine()) != null) {
                        System.out.println(response);
                        if (response.startsWith("Nonce|")) {
                            nonceString = response;
                            System.out.println(nonceString);
                        }
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();

            String message;
            while ((message = userInput.readLine()) != null) {
                if (message.equals("key")) {
                    message = publicKeyStr;
                } else if (message.equals("nonce")) {
                    String[] nonceParts = nonceString.split("\\|", 2);
                    nonceString = nonceParts[1];
                    System.out.println(nonceString);
                    byte[] nonce = Base64.getDecoder().decode(nonceString);

                    Signature sig = Signature.getInstance("SHA256withRSA");
                    sig.initSign(privateKey);
                    sig.update(nonce);

                    byte[] signature = sig.sign();
                    String signatureStr = Base64.getEncoder().encodeToString(signature);

                    out.println(signatureStr);
                }
                out.println(message);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
        catch (Exception e) {
            e.printStackTrace();
        }
    }
}