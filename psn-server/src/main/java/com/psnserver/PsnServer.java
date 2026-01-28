package com.psnserver;

import com.psnserver.auth.MockAuthService;
import com.psnserver.http.HttpServer;
import com.psnserver.http.HttpsServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class PsnServer {
    private static final Logger logger = LoggerFactory.getLogger(PsnServer.class);

    private final MockAuthService authService;
    private final HttpServer httpServer;
    private final HttpsServer httpsServer;

    public PsnServer(int httpPort, int httpsPort) throws Exception {
        this.authService = new MockAuthService();
        this.httpServer = new HttpServer(httpPort, authService);

        // HTTPS server with TLS support
        if (httpsPort > 0 && httpsPort != httpPort) {
            this.httpsServer = new HttpsServer(httpsPort, authService);
        } else {
            this.httpsServer = null;
        }
    }

    public void start() throws Exception {
        httpServer.start();
        if (httpsServer != null) {
            httpsServer.start();
        }
    }

    public void stop() {
        httpServer.stop();
        if (httpsServer != null) {
            httpsServer.stop();
        }
    }

    public void addUser(String username, String password, String onlineId) {
        authService.addUser(username, password, onlineId);
    }

    public MockAuthService getAuthService() {
        return authService;
    }

    public boolean isRunning() {
        return httpServer.isRunning();
    }

    public static void main(String[] args) {
        logger.info("=================================");
        logger.info("PlayStation Network Mock Server");
        logger.info("=================================");

        int httpPort = 80;
        int httpsPort = 443;

        // Parse command line arguments
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-p", "--port" -> {
                    if (i + 1 < args.length) httpPort = Integer.parseInt(args[++i]);
                }
                case "-s", "--https-port" -> {
                    if (i + 1 < args.length) httpsPort = Integer.parseInt(args[++i]);
                }
                case "-u", "--add-user" -> {
                    // Format: username:password:onlineId
                    if (i + 1 < args.length) {
                        // Will be processed after server starts
                    }
                }
                case "-h", "--help" -> {
                    printHelp();
                    return;
                }
            }
        }

        try {
            PsnServer server = new PsnServer(httpPort, httpsPort);

            // Process user additions
            for (int i = 0; i < args.length; i++) {
                if ((args[i].equals("-u") || args[i].equals("--add-user")) && i + 1 < args.length) {
                    String[] parts = args[++i].split(":");
                    if (parts.length >= 3) {
                        server.addUser(parts[0], parts[1], parts[2]);
                    }
                }
            }

            // Add shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                logger.info("Shutting down...");
                server.stop();
            }));

            server.start();

            logger.info("");
            logger.info("Server is running!");
            logger.info("HTTP  Port: {}", httpPort);
            if (httpsPort > 0 && httpsPort != httpPort) {
                logger.info("HTTPS Port: {} (TLS enabled)", httpsPort);
            }
            logger.info("");
            logger.info("Default test credentials:");
            logger.info("  Username: test_user");
            logger.info("  Password: TestPass123!");
            logger.info("  Online ID: TestPlayer");
            logger.info("");
            logger.info("Press Ctrl+C to stop.");

            // Keep main thread alive
            while (server.isRunning()) {
                Thread.sleep(1000);
            }

        } catch (java.net.BindException e) {
            logger.error("Cannot bind to port: {}", e.getMessage());
            logger.error("Try running with sudo or use ports > 1024");
            System.exit(1);
        } catch (Exception e) {
            logger.error("Failed to start server: {}", e.getMessage(), e);
            System.exit(1);
        }
    }

    private static void printHelp() {
        System.out.println("PlayStation Network Mock Server");
        System.out.println();
        System.out.println("Usage: java -jar psn-server.jar [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -p, --port <port>       HTTP port (default: 80)");
        System.out.println("  -s, --https-port <port> HTTPS port (default: 443)");
        System.out.println("  -u, --add-user <u:p:id> Add user (username:password:onlineId)");
        System.out.println("  -h, --help              Show this help");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  sudo java -jar psn-server.jar");
        System.out.println("  sudo java -jar psn-server.jar -u myuser:mypass:MyPSNName");
        System.out.println("  java -jar psn-server.jar -p 8080 -s 8443");
    }
}
