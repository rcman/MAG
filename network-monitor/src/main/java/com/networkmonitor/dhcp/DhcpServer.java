package com.networkmonitor.dhcp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * DHCP Server implementation for the network monitor.
 */
public class DhcpServer implements Runnable {
    private static final Logger logger = LoggerFactory.getLogger(DhcpServer.class);

    private static final int DHCP_SERVER_PORT = 67;
    private static final int DHCP_CLIENT_PORT = 68;

    private final InetAddress serverIp;
    private final InetAddress gateway;
    private final InetAddress subnetMask;
    private final InetAddress dnsServer;
    private final InetAddress broadcastAddress;
    private final int leaseTimeSeconds;

    private final int rangeStart;
    private final int rangeEnd;
    private final Set<Integer> availableIps;
    private final Map<String, DhcpLease> leasesByMac;
    private final Map<Integer, String> ipToMac;

    private DatagramSocket socket;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread serverThread;

    private Consumer<DhcpLease> leaseListener;

    public DhcpServer(String serverIpStr, String gatewayStr, String subnetMaskStr,
                      String dnsStr, String rangeStartStr, String rangeEndStr,
                      int leaseHours) throws UnknownHostException {
        this.serverIp = InetAddress.getByName(serverIpStr);
        this.gateway = InetAddress.getByName(gatewayStr);
        this.subnetMask = InetAddress.getByName(subnetMaskStr);
        this.dnsServer = InetAddress.getByName(dnsStr);
        this.leaseTimeSeconds = leaseHours * 3600;

        // Calculate broadcast address (e.g., 10.0.0.255 for 10.0.0.1/255.255.255.0)
        byte[] ipBytes = serverIp.getAddress();
        byte[] maskBytes = subnetMask.getAddress();
        byte[] broadcastBytes = new byte[4];
        for (int i = 0; i < 4; i++) {
            broadcastBytes[i] = (byte) (ipBytes[i] | ~maskBytes[i]);
        }
        this.broadcastAddress = InetAddress.getByAddress(broadcastBytes);

        // Parse IP range
        this.rangeStart = parseLastOctet(rangeStartStr);
        this.rangeEnd = parseLastOctet(rangeEndStr);

        this.availableIps = Collections.synchronizedSet(new HashSet<>());
        for (int i = rangeStart; i <= rangeEnd; i++) {
            availableIps.add(i);
        }

        this.leasesByMac = new ConcurrentHashMap<>();
        this.ipToMac = new ConcurrentHashMap<>();

        logger.info("DHCP Server initialized: range {}-{}, gateway {}, broadcast {}",
                rangeStartStr, rangeEndStr, gatewayStr, broadcastAddress.getHostAddress());
    }

    private int parseLastOctet(String ip) {
        String[] parts = ip.split("\\.");
        return Integer.parseInt(parts[3]);
    }

    public void setLeaseListener(Consumer<DhcpLease> listener) {
        this.leaseListener = listener;
    }

    public void start() throws SocketException {
        if (running.get()) {
            logger.warn("DHCP server already running");
            return;
        }

        // Bind to the specific server IP to ensure broadcasts go out the right interface
        socket = new DatagramSocket(null);
        socket.setReuseAddress(true);
        socket.setBroadcast(true);
        socket.bind(new InetSocketAddress(serverIp, DHCP_SERVER_PORT));

        running.set(true);
        serverThread = new Thread(this, "DHCP-Server");
        serverThread.setDaemon(true);
        serverThread.start();

        logger.info("DHCP server started on {}:{}", serverIp.getHostAddress(), DHCP_SERVER_PORT);
        logger.info("Make sure firewall allows UDP ports 67 and 68");
    }

    public void stop() {
        running.set(false);
        if (socket != null && !socket.isClosed()) {
            socket.close();
        }
        if (serverThread != null) {
            serverThread.interrupt();
        }
        logger.info("DHCP server stopped");
    }

    public boolean isRunning() {
        return running.get();
    }

    @Override
    public void run() {
        byte[] buffer = new byte[1024];
        logger.info("DHCP server listening for packets...");

        while (running.get()) {
            try {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                socket.receive(packet);

                logger.info("Received packet from {} ({} bytes)",
                        packet.getAddress().getHostAddress(), packet.getLength());

                byte[] data = Arrays.copyOf(packet.getData(), packet.getLength());
                handlePacket(data, packet.getAddress());

            } catch (SocketException e) {
                if (running.get()) {
                    logger.error("Socket error in DHCP server", e);
                }
            } catch (Exception e) {
                logger.error("Error processing DHCP packet", e);
            }
        }
    }

    private void handlePacket(byte[] data, InetAddress clientAddress) {
        try {
            DhcpPacket request = DhcpPacket.parse(data);

            // Only process client requests (op = 1)
            if (request.getOp() != 1) {
                return;
            }

            String mac = request.getMacAddressString();
            byte messageType = request.getMessageType();

            logger.info("DHCP {} received from {}", DhcpPacket.messageTypeName(messageType), mac);

            switch (messageType) {
                case DhcpPacket.DHCP_DISCOVER:
                    handleDiscover(request, mac);
                    break;
                case DhcpPacket.DHCP_REQUEST:
                    handleRequest(request, mac);
                    break;
                case DhcpPacket.DHCP_RELEASE:
                    handleRelease(request, mac);
                    break;
                case DhcpPacket.DHCP_DECLINE:
                    handleDecline(request, mac);
                    break;
            }
        } catch (Exception e) {
            logger.error("Error handling DHCP packet", e);
        }
    }

    private void handleDiscover(DhcpPacket request, String mac) throws Exception {
        InetAddress offeredIp = allocateIp(mac);
        if (offeredIp == null) {
            logger.warn("No available IP addresses for {}", mac);
            return;
        }

        DhcpPacket offer = DhcpPacket.createOffer(request, offeredIp, serverIp,
                gateway, subnetMask, dnsServer, leaseTimeSeconds);

        sendPacket(offer);
        logger.info("DHCP OFFER {} to {}", offeredIp.getHostAddress(), mac);
    }

    private void handleRequest(DhcpPacket request, String mac) throws Exception {
        InetAddress requestedIp = request.getRequestedIp();
        if (requestedIp == null) {
            requestedIp = request.getCiaddr();
        }

        // Check if this MAC already has a lease
        DhcpLease existingLease = leasesByMac.get(mac);
        InetAddress assignedIp;

        if (existingLease != null && !existingLease.isExpired()) {
            assignedIp = existingLease.getIpAddress();
        } else if (requestedIp != null && isIpAvailableFor(requestedIp, mac)) {
            assignedIp = requestedIp;
        } else {
            assignedIp = allocateIp(mac);
        }

        if (assignedIp == null) {
            DhcpPacket nak = DhcpPacket.createNak(request, serverIp);
            sendPacket(nak);
            logger.warn("DHCP NAK to {} - no available IP", mac);
            return;
        }

        // Create or update lease
        DhcpLease lease = new DhcpLease(mac, assignedIp, leaseTimeSeconds);
        if (request.getHostname() != null) {
            lease.setHostname(request.getHostname());
        }

        // Update tracking
        int lastOctet = assignedIp.getAddress()[3] & 0xFF;
        availableIps.remove(lastOctet);
        ipToMac.put(lastOctet, mac);
        leasesByMac.put(mac, lease);

        DhcpPacket ack = DhcpPacket.createAck(request, assignedIp, serverIp,
                gateway, subnetMask, dnsServer, leaseTimeSeconds);

        sendPacket(ack);
        logger.info("DHCP ACK {} to {} ({})", assignedIp.getHostAddress(), mac,
                lease.getHostname() != null ? lease.getHostname() : "no hostname");

        if (leaseListener != null) {
            leaseListener.accept(lease);
        }
    }

    private void handleRelease(DhcpPacket request, String mac) {
        DhcpLease lease = leasesByMac.remove(mac);
        if (lease != null) {
            int lastOctet = lease.getIpAddress().getAddress()[3] & 0xFF;
            availableIps.add(lastOctet);
            ipToMac.remove(lastOctet);
            logger.info("DHCP RELEASE {} from {}", lease.getIpAddress().getHostAddress(), mac);
        }
    }

    private void handleDecline(DhcpPacket request, String mac) {
        InetAddress declinedIp = request.getRequestedIp();
        if (declinedIp != null) {
            int lastOctet = declinedIp.getAddress()[3] & 0xFF;
            // Mark IP as unavailable (could be in use by another device)
            availableIps.remove(lastOctet);
            logger.warn("DHCP DECLINE {} from {} - marking IP unavailable",
                    declinedIp.getHostAddress(), mac);
        }
    }

    private InetAddress allocateIp(String mac) throws UnknownHostException {
        // Check if MAC already has a valid lease
        DhcpLease existingLease = leasesByMac.get(mac);
        if (existingLease != null && !existingLease.isExpired()) {
            return existingLease.getIpAddress();
        }

        // Find an available IP
        synchronized (availableIps) {
            if (availableIps.isEmpty()) {
                return null;
            }
            Integer ip = availableIps.iterator().next();
            byte[] addr = serverIp.getAddress();
            addr[3] = ip.byteValue();
            return InetAddress.getByAddress(addr);
        }
    }

    private boolean isIpAvailableFor(InetAddress ip, String mac) {
        int lastOctet = ip.getAddress()[3] & 0xFF;
        if (lastOctet < rangeStart || lastOctet > rangeEnd) {
            return false;
        }

        String assignedMac = ipToMac.get(lastOctet);
        return assignedMac == null || assignedMac.equals(mac);
    }

    private void sendPacket(DhcpPacket packet) throws Exception {
        byte[] data = packet.build();
        // Send to subnet broadcast address (e.g., 10.0.0.255) to ensure it goes out the right interface
        DatagramPacket dgram = new DatagramPacket(data, data.length,
                broadcastAddress, DHCP_CLIENT_PORT);
        socket.send(dgram);
        logger.info("Sent DHCP response to {} ({} bytes)", broadcastAddress.getHostAddress(), data.length);
    }

    public Collection<DhcpLease> getActiveLeases() {
        // Remove expired leases and return active ones
        leasesByMac.entrySet().removeIf(entry -> {
            if (entry.getValue().isExpired()) {
                int lastOctet = entry.getValue().getIpAddress().getAddress()[3] & 0xFF;
                availableIps.add(lastOctet);
                ipToMac.remove(lastOctet);
                return true;
            }
            return false;
        });
        return new ArrayList<>(leasesByMac.values());
    }

    public int getAvailableIpCount() {
        return availableIps.size();
    }

    public int getActiveLeaseCount() {
        return leasesByMac.size();
    }
}
