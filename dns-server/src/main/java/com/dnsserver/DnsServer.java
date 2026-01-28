package com.dnsserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

public class DnsServer {
    private static final Logger logger = LoggerFactory.getLogger(DnsServer.class);

    private static final int DNS_PORT = 53;
    private static final int BUFFER_SIZE = 512;
    private static final int DEFAULT_TTL = 300; // 5 minutes

    private final DomainResolver resolver;
    private final int port;
    private final String bindAddress;
    private final int ttl;
    private final boolean forwardUnknown;

    private DatagramSocket socket;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final ExecutorService executor;

    // Statistics
    private final AtomicLong totalQueries = new AtomicLong(0);
    private final AtomicLong localResponses = new AtomicLong(0);
    private final AtomicLong forwardedQueries = new AtomicLong(0);
    private final AtomicLong errors = new AtomicLong(0);

    public DnsServer(DomainResolver resolver) {
        this(resolver, DNS_PORT, "0.0.0.0", DEFAULT_TTL, true);
    }

    public DnsServer(DomainResolver resolver, int port, String bindAddress, int ttl, boolean forwardUnknown) {
        this.resolver = resolver;
        this.port = port;
        this.bindAddress = bindAddress;
        this.ttl = ttl;
        this.forwardUnknown = forwardUnknown;
        this.executor = Executors.newFixedThreadPool(4);
    }

    public void start() throws IOException {
        InetAddress addr = InetAddress.getByName(bindAddress);
        socket = new DatagramSocket(port, addr);
        running.set(true);

        logger.info("DNS Server started on {}:{}", bindAddress, port);
        logger.info("TTL: {} seconds, Forward unknown: {}", ttl, forwardUnknown);

        Thread serverThread = new Thread(this::serverLoop, "DNS-Server");
        serverThread.setDaemon(true);
        serverThread.start();
    }

    private void serverLoop() {
        byte[] buffer = new byte[BUFFER_SIZE];

        while (running.get()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                // Process in separate thread to handle concurrent requests
                byte[] data = new byte[packet.getLength()];
                System.arraycopy(packet.getData(), 0, data, 0, packet.getLength());

                final InetAddress clientAddr = packet.getAddress();
                final int clientPort = packet.getPort();

                executor.submit(() -> handleQuery(data, clientAddr, clientPort));

            } catch (IOException e) {
                if (running.get()) {
                    logger.error("Error receiving packet: {}", e.getMessage());
                    errors.incrementAndGet();
                }
            }
        }
    }

    private void handleQuery(byte[] data, InetAddress clientAddr, int clientPort) {
        totalQueries.incrementAndGet();

        try {
            DnsMessage query = DnsMessage.parse(data);

            if (!query.isQuery()) {
                logger.debug("Ignoring non-query packet");
                return;
            }

            for (DnsMessage.DnsQuestion question : query.getQuestions()) {
                logger.info("DNS Query from {}: {} ({})",
                        clientAddr.getHostAddress(),
                        question.name,
                        question.getTypeString());

                byte[] response;
                String resolvedIp = resolver.resolve(question.name);

                if (resolvedIp != null) {
                    // We have a local answer
                    response = query.buildResponse(resolvedIp, ttl);
                    localResponses.incrementAndGet();
                    logger.info("Resolved {} -> {} (local)", question.name, resolvedIp);
                } else if (forwardUnknown) {
                    // Forward to upstream DNS
                    response = forwardQuery(data, question.name);
                    if (response == null) {
                        response = query.buildNxdomainResponse();
                    }
                    forwardedQueries.incrementAndGet();
                } else {
                    // Return NXDOMAIN
                    response = query.buildNxdomainResponse();
                    logger.debug("No resolution for {}, returning NXDOMAIN", question.name);
                }

                // Send response
                DatagramPacket responsePacket = new DatagramPacket(
                        response, response.length, clientAddr, clientPort);
                socket.send(responsePacket);
            }

        } catch (Exception e) {
            logger.error("Error handling query: {}", e.getMessage());
            errors.incrementAndGet();
        }
    }

    private byte[] forwardQuery(byte[] query, String domain) {
        try (DatagramSocket forwardSocket = new DatagramSocket()) {
            forwardSocket.setSoTimeout(3000); // 3 second timeout

            InetAddress upstreamAddr = InetAddress.getByName(resolver.getUpstreamDns());
            DatagramPacket forwardPacket = new DatagramPacket(query, query.length, upstreamAddr, DNS_PORT);
            forwardSocket.send(forwardPacket);

            byte[] responseBuffer = new byte[BUFFER_SIZE];
            DatagramPacket responsePacket = new DatagramPacket(responseBuffer, responseBuffer.length);
            forwardSocket.receive(responsePacket);

            byte[] response = new byte[responsePacket.getLength()];
            System.arraycopy(responsePacket.getData(), 0, response, 0, responsePacket.getLength());

            logger.debug("Forwarded query for {} to upstream DNS", domain);
            return response;

        } catch (SocketTimeoutException e) {
            logger.warn("Timeout forwarding query for {} to upstream DNS", domain);
            return null;
        } catch (IOException e) {
            logger.error("Error forwarding query: {}", e.getMessage());
            return null;
        }
    }

    public void stop() {
        running.set(false);
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
        executor.shutdown();
        logger.info("DNS Server stopped");
        printStatistics();
    }

    public void printStatistics() {
        logger.info("=== DNS Server Statistics ===");
        logger.info("Total queries: {}", totalQueries.get());
        logger.info("Local responses: {}", localResponses.get());
        logger.info("Forwarded queries: {}", forwardedQueries.get());
        logger.info("Errors: {}", errors.get());
    }

    public boolean isRunning() {
        return running.get();
    }

    public static void main(String[] args) {
        logger.info("PlayStation DNS Server v1.0");
        logger.info("=============================");

        // Parse command line arguments
        String configPath = "domains.properties";
        String bindAddress = "0.0.0.0";
        int port = DNS_PORT;
        int ttl = DEFAULT_TTL;
        boolean forwardUnknown = true;

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-c", "--config" -> {
                    if (i + 1 < args.length) configPath = args[++i];
                }
                case "-b", "--bind" -> {
                    if (i + 1 < args.length) bindAddress = args[++i];
                }
                case "-p", "--port" -> {
                    if (i + 1 < args.length) port = Integer.parseInt(args[++i]);
                }
                case "-t", "--ttl" -> {
                    if (i + 1 < args.length) ttl = Integer.parseInt(args[++i]);
                }
                case "--no-forward" -> forwardUnknown = false;
                case "-h", "--help" -> {
                    printHelp();
                    return;
                }
            }
        }

        // Load domain configuration
        DomainResolver resolver = new DomainResolver();
        resolver.loadConfig(configPath);

        // Create and start server
        DnsServer server = new DnsServer(resolver, port, bindAddress, ttl, forwardUnknown);

        // Add shutdown hook
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            logger.info("Shutting down...");
            server.stop();
        }));

        try {
            server.start();

            // Keep main thread alive
            logger.info("DNS Server is running. Press Ctrl+C to stop.");
            while (server.isRunning()) {
                Thread.sleep(1000);
            }
        } catch (BindException e) {
            logger.error("Cannot bind to port {}: {}", port, e.getMessage());
            logger.error("Try running with sudo or use a port > 1024");
            System.exit(1);
        } catch (IOException e) {
            logger.error("Failed to start DNS server: {}", e.getMessage());
            System.exit(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void printHelp() {
        System.out.println("PlayStation DNS Server");
        System.out.println();
        System.out.println("Usage: java -jar dns-server.jar [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -c, --config <file>   Domain configuration file (default: domains.properties)");
        System.out.println("  -b, --bind <address>  Bind address (default: 0.0.0.0)");
        System.out.println("  -p, --port <port>     DNS port (default: 53)");
        System.out.println("  -t, --ttl <seconds>   TTL for DNS responses (default: 300)");
        System.out.println("  --no-forward          Don't forward unknown domains to upstream DNS");
        System.out.println("  -h, --help            Show this help message");
        System.out.println();
        System.out.println("The domains.properties file format:");
        System.out.println("  server.ip=10.0.0.1");
        System.out.println("  upstream.dns=8.8.8.8");
        System.out.println("  fus01.ps3.update.playstation.net=${server.ip}");
        System.out.println("  *.playstation.net=${server.ip}");
    }
}
