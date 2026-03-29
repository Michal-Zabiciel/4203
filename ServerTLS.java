import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import javax.net.ssl.*;

public class Server {
    private static final int PORT = 12345;
    private static Map<String, PrintWriter> clients = new HashMap<>();

    public static void main(String[] args) {
        System.out.println("Server started...");

        try (ServerSocket serverSocket = new SSLServerSocket(PORT)) {
            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New client connected");

                new Thread(new ClientHandler(clientSocket)).start();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    static class ClientHandler implements Runnable {
        private Socket socket;
        private BufferedReader in;
        private PrintWriter out;
        private String username;
        private boolean impostor = false;

        public ClientHandler(Socket socket) {
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