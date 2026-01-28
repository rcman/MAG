package com.psnserver.http;

import com.psnserver.auth.MockAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class HttpsServer {
    private static final Logger logger = LoggerFactory.getLogger(HttpsServer.class);

    private final int port;
    private final RequestHandler requestHandler;
    private final ExecutorService executor;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private SSLServerSocket serverSocket;

    public HttpsServer(int port, MockAuthService authService) {
        this.port = port;
        this.requestHandler = new RequestHandler(authService);
        this.executor = Executors.newFixedThreadPool(10);
    }

    public void start() throws Exception {
        SSLContext sslContext = createSSLContext();
        SSLServerSocketFactory factory = sslContext.getServerSocketFactory();
        serverSocket = (SSLServerSocket) factory.createServerSocket(port);

        // Enable all protocols and ciphers for compatibility with PS3
        serverSocket.setEnabledProtocols(new String[]{"TLSv1", "TLSv1.1", "TLSv1.2", "SSLv3"});

        running.set(true);
        logger.info("HTTPS Server started on port {} (TLS enabled)", port);

        Thread serverThread = new Thread(this::acceptConnections, "HTTPS-Server");
        serverThread.setDaemon(true);
        serverThread.start();
    }

    private SSLContext createSSLContext() throws Exception {
        // Try to load existing keystore, or create new one
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        File keystoreFile = new File("keystore.p12");
        if (keystoreFile.exists()) {
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keyStore.load(fis, "changeit".toCharArray());
                logger.info("Loaded existing keystore");
            }
        } else {
            // Generate self-signed certificate
            logger.info("Generating self-signed certificate...");
            generateSelfSignedCert();
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keyStore.load(fis, "changeit".toCharArray());
            }
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "changeit".toCharArray());

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return sslContext;
    }

    private void generateSelfSignedCert() throws Exception {
        ProcessBuilder pb = new ProcessBuilder(
                "keytool", "-genkeypair",
                "-alias", "psnserver",
                "-keyalg", "RSA",
                "-keysize", "2048",
                "-validity", "365",
                "-keystore", "keystore.p12",
                "-storetype", "PKCS12",
                "-storepass", "changeit",
                "-keypass", "changeit",
                "-dname", "CN=*.playstation.net, OU=PSN, O=Sony, L=Tokyo, ST=Tokyo, C=JP",
                "-ext", "san=dns:*.playstation.net,dns:*.playstation.com,dns:*.sonyentertainmentnetwork.com,dns:localhost,ip:10.0.0.1"
        );
        pb.inheritIO();
        Process process = pb.start();
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Failed to generate certificate");
        }
        logger.info("Generated self-signed certificate");
    }

    private void acceptConnections() {
        while (running.get()) {
            try {
                Socket clientSocket = serverSocket.accept();
                executor.submit(() -> handleClient(clientSocket));
            } catch (IOException e) {
                if (running.get()) {
                    logger.error("Error accepting connection: {}", e.getMessage());
                }
            }
        }
    }

    private void handleClient(Socket clientSocket) {
        String clientAddr = clientSocket.getInetAddress().getHostAddress();

        try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
             OutputStream out = clientSocket.getOutputStream()) {

            // Read request line
            String requestLine = in.readLine();
            if (requestLine == null || requestLine.isEmpty()) {
                return;
            }

            logger.info("HTTPS Request from {}: {}", clientAddr, requestLine);

            // Parse request
            String[] parts = requestLine.split(" ");
            if (parts.length < 2) {
                sendError(out, 400, "Bad Request");
                return;
            }

            String method = parts[0];
            String path = parts[1];

            // Read headers
            Map<String, String> headers = new HashMap<>();
            String headerLine;
            int contentLength = 0;
            while ((headerLine = in.readLine()) != null && !headerLine.isEmpty()) {
                int colonIndex = headerLine.indexOf(':');
                if (colonIndex > 0) {
                    String key = headerLine.substring(0, colonIndex).trim().toLowerCase();
                    String value = headerLine.substring(colonIndex + 1).trim();
                    headers.put(key, value);
                    if (key.equals("content-length")) {
                        contentLength = Integer.parseInt(value);
                    }
                }
            }

            // Read body if present
            String body = "";
            if (contentLength > 0) {
                char[] bodyChars = new char[contentLength];
                int read = in.read(bodyChars, 0, contentLength);
                if (read > 0) {
                    body = new String(bodyChars, 0, read);
                }
            }

            // Create request object
            HttpServer.HttpRequest request = new HttpServer.HttpRequest(method, path, headers, body);

            // Handle request
            HttpServer.HttpResponse response = requestHandler.handle(request);

            // Send response
            sendResponse(out, response);

        } catch (SSLHandshakeException e) {
            logger.warn("SSL handshake failed from {}: {}", clientAddr, e.getMessage());
        } catch (Exception e) {
            logger.error("Error handling HTTPS client {}: {}", clientAddr, e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }

    private void sendResponse(OutputStream out, HttpServer.HttpResponse response) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append("HTTP/1.1 ").append(response.getStatusCode()).append(" ").append(response.getStatusMessage()).append("\r\n");

        for (Map.Entry<String, String> header : response.getHeaders().entrySet()) {
            sb.append(header.getKey()).append(": ").append(header.getValue()).append("\r\n");
        }

        byte[] bodyBytes = response.getBody().getBytes(StandardCharsets.UTF_8);
        sb.append("Content-Length: ").append(bodyBytes.length).append("\r\n");
        sb.append("Connection: close\r\n");
        sb.append("\r\n");

        out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
        out.write(bodyBytes);
        out.flush();
    }

    private void sendError(OutputStream out, int code, String message) throws IOException {
        HttpServer.HttpResponse response = new HttpServer.HttpResponse(code, message);
        response.setBody("{\"error\": \"" + message + "\"}");
        response.addHeader("Content-Type", "application/json");
        sendResponse(out, response);
    }

    public void stop() {
        running.set(false);
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            // Ignore
        }
        executor.shutdown();
        logger.info("HTTPS Server stopped");
    }

    public boolean isRunning() {
        return running.get();
    }
}
