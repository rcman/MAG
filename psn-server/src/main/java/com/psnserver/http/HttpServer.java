package com.psnserver.http;

import com.psnserver.auth.MockAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

public class HttpServer {
    private static final Logger logger = LoggerFactory.getLogger(HttpServer.class);

    private final int port;
    private final MockAuthService authService;
    private final RequestHandler requestHandler;
    private final ExecutorService executor;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private ServerSocket serverSocket;

    public HttpServer(int port, MockAuthService authService) {
        this.port = port;
        this.authService = authService;
        this.requestHandler = new RequestHandler(authService);
        this.executor = Executors.newFixedThreadPool(10);
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port);
        running.set(true);

        logger.info("HTTP Server started on port {}", port);

        Thread serverThread = new Thread(this::acceptConnections, "HTTP-Server");
        serverThread.setDaemon(true);
        serverThread.start();
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

            logger.info("Request from {}: {}", clientAddr, requestLine);

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
            HttpRequest request = new HttpRequest(method, path, headers, body);

            // Handle request
            HttpResponse response = requestHandler.handle(request);

            // Send response
            sendResponse(out, response);

        } catch (Exception e) {
            logger.error("Error handling client {}: {}", clientAddr, e.getMessage());
        } finally {
            try {
                clientSocket.close();
            } catch (IOException e) {
                // Ignore
            }
        }
    }

    private void sendResponse(OutputStream out, HttpResponse response) throws IOException {
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
        HttpResponse response = new HttpResponse(code, message);
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
        logger.info("HTTP Server stopped");
    }

    public boolean isRunning() {
        return running.get();
    }

    // Request class
    public static class HttpRequest {
        private final String method;
        private final String path;
        private final Map<String, String> headers;
        private final String body;

        public HttpRequest(String method, String path, Map<String, String> headers, String body) {
            this.method = method;
            this.path = path;
            this.headers = headers;
            this.body = body;
        }

        public String getMethod() { return method; }
        public String getPath() { return path; }
        public Map<String, String> getHeaders() { return headers; }
        public String getBody() { return body; }
        public String getHeader(String name) { return headers.get(name.toLowerCase()); }
    }

    // Response class
    public static class HttpResponse {
        private int statusCode;
        private String statusMessage;
        private Map<String, String> headers = new HashMap<>();
        private String body = "";

        public HttpResponse(int statusCode, String statusMessage) {
            this.statusCode = statusCode;
            this.statusMessage = statusMessage;
        }

        public int getStatusCode() { return statusCode; }
        public String getStatusMessage() { return statusMessage; }
        public Map<String, String> getHeaders() { return headers; }
        public String getBody() { return body; }

        public void addHeader(String name, String value) { headers.put(name, value); }
        public void setBody(String body) { this.body = body; }
    }
}
