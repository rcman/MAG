package com.networkmonitor.parser;

import org.pcap4j.packet.UdpPacket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Parser for UDP datagrams.
 */
public class UdpParser {
    private static final Logger logger = LoggerFactory.getLogger(UdpParser.class);

    public String parse(UdpPacket packet, String srcIp, String dstIp) {
        UdpPacket.UdpHeader header = packet.getHeader();

        int srcPort = header.getSrcPort().valueAsInt();
        int dstPort = header.getDstPort().valueAsInt();
        int length = header.getLength();

        int payloadSize = packet.getPayload() != null ? packet.getPayload().length() : 0;

        StringBuilder result = new StringBuilder();
        result.append("UDP | ");
        result.append(srcIp).append(":").append(srcPort);
        result.append(" -> ");
        result.append(dstIp).append(":").append(dstPort);
        result.append(" | Size: ").append(payloadSize).append("B");

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

    private String getPortDescription(int port) {
        return switch (port) {
            case 53 -> "DNS";
            case 67, 68 -> "DHCP";
            case 69 -> "TFTP";
            case 123 -> "NTP";
            case 137, 138 -> "NetBIOS";
            case 161, 162 -> "SNMP";
            case 500 -> "IKE";
            case 514 -> "Syslog";
            case 520 -> "RIP";
            case 1194 -> "OpenVPN";
            case 1900 -> "SSDP";
            case 4500 -> "NAT-T";
            case 5353 -> "mDNS";
            case 5355 -> "LLMNR";
            case 51820 -> "WireGuard";
            default -> null;
        };
    }
}
