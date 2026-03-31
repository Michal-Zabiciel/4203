import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import javax.net.ssl.*;

public class FakeServer {
    private static final String host = "localhost";
    private static final int port = 12345;
    private static Map<String, PrintWriter> clients = new HashMap<>();

    public static void main(String[] args) {
        System.out.println("Server started...");

        try {
            char[] password = "password".toCharArray();
            KeyStore keyStore = KeyStore.getInstance("JKS");

            try (FileInputStream fis = new FileInputStream("keystore.jks")) {
                keyStore.load(fis, password);
            }
            
            
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(keyStore, password);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, null);

            SSLServerSocketFactory ssf = sslContext.getServerSocketFactory();

            SSLServerSocket serverSocket = (SSLServerSocket) ssf.createServerSocket(port);

            // enable all the cipher suites
            String[] supported = serverSocket.getSupportedCipherSuites();
            serverSocket.setEnabledCipherSuites(supported);

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

    static class ClientHandler implements Runnable {
        private SSLSocket socket;
        private BufferedReader in;
        private PrintWriter out;
        private String username;
        private boolean impostor = false;

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
                        impostor = true;
                        socket.close();
                        return;
                    }
                    clients.put(username, out);
                }

                System.out.println(username + " connected.");

                String fullMessage;
                while ((fullMessage = in.readLine()) != null) {
                    System.out.println("Received: " + fullMessage);

                    String[] parts = fullMessage.split("\\|", 2);
                    if (parts.length < 2)  {
                        out.println("Invalid message format. Use target|message");
                        continue;
                    }

                    String target = parts[0];
                    String message = parts[1];

                    synchronized (clients) {
                        PrintWriter writer = clients.get(target);
                        if (writer != null) {
                            writer.println(username + ": " + message);
                        } else {
                            out.println("User " + target + " not connected.");
                        }
                    }
                }
            } catch (IOException e) {
                System.out.println("Client disconnected");
            } finally {
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