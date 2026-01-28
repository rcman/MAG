package com.networkmonitor.capture;

import com.networkmonitor.logging.TrafficLogger;
import com.networkmonitor.parser.*;
import org.pcap4j.packet.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.function.Consumer;

/**
 * Handles captured packets and routes them to appropriate parsers.
 */
public class PacketHandler {
    private static final Logger logger = LoggerFactory.getLogger(PacketHandler.class);

    private final DnsParser dnsParser;
    private final HttpParser httpParser;
    private final TcpParser tcpParser;
    private final UdpParser udpParser;
    private final TrafficLogger trafficLogger;

    private Consumer<String> trafficListener;
    private long packetCount = 0;
    private long tcpCount = 0;
    private long udpCount = 0;
    private long dnsCount = 0;
    private long httpCount = 0;

    public PacketHandler(TrafficLogger trafficLogger) {
        this.trafficLogger = trafficLogger;
        this.dnsParser = new DnsParser();
        this.httpParser = new HttpParser();
        this.tcpParser = new TcpParser();
        this.udpParser = new UdpParser();
    }

    public void setTrafficListener(Consumer<String> listener) {
        this.trafficListener = listener;
    }

    public void handlePacket(Packet packet) {
        if (packet == null) return;

        packetCount++;

        try {
            // Extract IP layer
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            if (ipPacket == null) {
                IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
                if (ipV6Packet != null) {
                    handleIpV6Packet(ipV6Packet);
                }
                return;
            }

            handleIpV4Packet(ipPacket);

        } catch (Exception e) {
            logger.debug("Error processing packet: {}", e.getMessage());
        }
    }

    private void handleIpV4Packet(IpV4Packet ipPacket) {
        String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();

        // Check for TCP
        TcpPacket tcpPacket = ipPacket.get(TcpPacket.class);
        if (tcpPacket != null) {
            handleTcpPacket(tcpPacket, srcIp, dstIp);
            return;
        }

        // Check for UDP
        UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
        if (udpPacket != null) {
            handleUdpPacket(udpPacket, srcIp, dstIp);
        }
    }

    private void handleIpV6Packet(IpV6Packet ipPacket) {
        String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();

        TcpPacket tcpPacket = ipPacket.get(TcpPacket.class);
        if (tcpPacket != null) {
            handleTcpPacket(tcpPacket, srcIp, dstIp);
            return;
        }

        UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
        if (udpPacket != null) {
            handleUdpPacket(udpPacket, srcIp, dstIp);
        }
    }

    private void handleTcpPacket(TcpPacket tcpPacket, String srcIp, String dstIp) {
        tcpCount++;

        int srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
        int dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();

        // Parse TCP flags and connection info
        String tcpInfo = tcpParser.parse(tcpPacket, srcIp, dstIp);
        logTraffic(tcpInfo);

        // Check for HTTP (port 80)
        if (srcPort == 80 || dstPort == 80) {
            byte[] payload = tcpPacket.getPayload() != null ?
                    tcpPacket.getPayload().getRawData() : null;
            if (payload != null && payload.length > 0) {
                String httpInfo = httpParser.parse(payload, srcIp, srcPort, dstIp, dstPort);
                if (httpInfo != null) {
                    httpCount++;
                    logTraffic(httpInfo);
                }
            }
        }

        // HTTPS (port 443) - only log connection metadata
        if (srcPort == 443 || dstPort == 443) {
            if (tcpPacket.getHeader().getSyn() && !tcpPacket.getHeader().getAck()) {
                String httpsInfo = String.format("HTTPS CONNECT | %s:%d -> %s:%d",
                        srcIp, srcPort, dstIp, dstPort);
                logTraffic(httpsInfo);
            }
        }
    }

    private void handleUdpPacket(UdpPacket udpPacket, String srcIp, String dstIp) {
        udpCount++;

        int srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
        int dstPort = udpPacket.getHeader().getDstPort().valueAsInt();

        // Check for DNS (port 53)
        if (srcPort == 53 || dstPort == 53) {
            byte[] payload = udpPacket.getPayload() != null ?
                    udpPacket.getPayload().getRawData() : null;
            if (payload != null && payload.length > 0) {
                String dnsInfo = dnsParser.parse(payload, srcIp, dstIp);
                if (dnsInfo != null) {
                    dnsCount++;
                    logTraffic(dnsInfo);
                }
            }
            return;
        }

        // Skip DHCP packets (handled separately)
        if (srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68) {
            return;
        }

        // General UDP traffic
        String udpInfo = udpParser.parse(udpPacket, srcIp, dstIp);
        logTraffic(udpInfo);
    }

    private void logTraffic(String info) {
        if (info == null) return;

        trafficLogger.log(info);

        if (trafficListener != null) {
            trafficListener.accept(info);
        }
    }

    // Statistics getters
    public long getPacketCount() { return packetCount; }
    public long getTcpCount() { return tcpCount; }
    public long getUdpCount() { return udpCount; }
    public long getDnsCount() { return dnsCount; }
    public long getHttpCount() { return httpCount; }

    public void resetStats() {
        packetCount = 0;
        tcpCount = 0;
        udpCount = 0;
        dnsCount = 0;
        httpCount = 0;
    }
}
