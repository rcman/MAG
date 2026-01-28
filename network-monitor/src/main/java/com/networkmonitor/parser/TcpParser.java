package com.networkmonitor.parser;

import org.pcap4j.packet.TcpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Parser and tracker for TCP connections.
 */
public class TcpParser {
    private static final Logger logger = LoggerFactory.getLogger(TcpParser.class);

    // Track active TCP connections
    private final Map<String, TcpConnection> connections = new ConcurrentHashMap<>();

    public String parse(TcpPacket packet, String srcIp, String dstIp) {
        TcpPacket.TcpHeader header = packet.getHeader();

        int srcPort = header.getSrcPort().valueAsInt();
        int dstPort = header.getDstPort().valueAsInt();

        boolean syn = header.getSyn();
        boolean ack = header.getAck();
        boolean fin = header.getFin();
        boolean rst = header.getRst();
        boolean psh = header.getPsh();

        int payloadSize = packet.getPayload() != null ? packet.getPayload().length() : 0;

        StringBuilder result = new StringBuilder();
        result.append("TCP ");

        // Build flags string
        List<String> flags = new ArrayList<>();
        if (syn) flags.add("SYN");
        if (ack) flags.add("ACK");
        if (fin) flags.add("FIN");
        if (rst) flags.add("RST");
        if (psh) flags.add("PSH");

        result.append(String.join(",", flags));
        result.append(" | ");
        result.append(srcIp).append(":").append(srcPort);
        result.append(" -> ");
        result.append(dstIp).append(":").append(dstPort);

        // Track connection state
        String connKey = getConnectionKey(srcIp, srcPort, dstIp, dstPort);
        String reverseKey = getConnectionKey(dstIp, dstPort, srcIp, srcPort);

        if (syn && !ack) {
            // New connection attempt
            TcpConnection conn = new TcpConnection(srcIp, srcPort, dstIp, dstPort);
            conn.state = "SYN_SENT";
            connections.put(connKey, conn);
            result.append(" | New connection");
        } else if (syn && ack) {
            // SYN-ACK response
            TcpConnection conn = connections.get(reverseKey);
            if (conn != null) {
                conn.state = "SYN_RECEIVED";
            }
        } else if (ack && !syn && !fin && !rst) {
            // Regular ACK or data
            TcpConnection conn = connections.get(connKey);
            if (conn == null) {
                conn = connections.get(reverseKey);
            }
            if (conn != null && "SYN_RECEIVED".equals(conn.state)) {
                conn.state = "ESTABLISHED";
            }
            if (payloadSize > 0) {
                if (conn != null) {
                    conn.bytesTransferred += payloadSize;
                }
                result.append(" | Data: ").append(payloadSize).append("B");
            }
        } else if (fin) {
            // Connection closing
            TcpConnection conn = connections.get(connKey);
            if (conn == null) {
                conn = connections.get(reverseKey);
            }
            if (conn != null) {
                conn.state = "CLOSING";
            }
            result.append(" | Closing");
        } else if (rst) {
            // Connection reset
            connections.remove(connKey);
            connections.remove(reverseKey);
            result.append(" | Reset");
        }

        // Add well-known port description
        String portDesc = getPortDescription(srcPort);
        if (portDesc == null) {
            portDesc = getPortDescription(dstPort);
        }
        if (portDesc != null) {
            result.append(" | ").append(portDesc);
        }

        return result.toString();
    }

    private String getConnectionKey(String ip1, int port1, String ip2, int port2) {
        return ip1 + ":" + port1 + "-" + ip2 + ":" + port2;
    }

    private String getPortDescription(int port) {
        return switch (port) {
            case 20, 21 -> "FTP";
            case 22 -> "SSH";
            case 23 -> "Telnet";
            case 25 -> "SMTP";
            case 53 -> "DNS";
            case 80 -> "HTTP";
            case 110 -> "POP3";
            case 143 -> "IMAP";
            case 443 -> "HTTPS";
            case 465, 587 -> "SMTP/TLS";
            case 993 -> "IMAPS";
            case 995 -> "POP3S";
            case 3306 -> "MySQL";
            case 5432 -> "PostgreSQL";
            case 6379 -> "Redis";
            case 8080, 8443 -> "HTTP-Alt";
            default -> null;
        };
    }

    public int getActiveConnectionCount() {
        // Clean up old/closed connections
        connections.entrySet().removeIf(e ->
            "CLOSING".equals(e.getValue().state) ||
            System.currentTimeMillis() - e.getValue().lastActivity > 300000 // 5 min timeout
        );
        return connections.size();
    }

    public void clearConnections() {
        connections.clear();
    }

    /**
     * Internal class to track TCP connection state.
     */
    private static class TcpConnection {
        final String srcIp;
        final int srcPort;
        final String dstIp;
        final int dstPort;
        String state;
        long bytesTransferred;
        long lastActivity;

        TcpConnection(String srcIp, int srcPort, String dstIp, int dstPort) {
            this.srcIp = srcIp;
            this.srcPort = srcPort;
            this.dstIp = dstIp;
            this.dstPort = dstPort;
            this.state = "NEW";
            this.bytesTransferred = 0;
            this.lastActivity = System.currentTimeMillis();
        }
    }
}
