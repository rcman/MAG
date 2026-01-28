package com.networkmonitor.dhcp;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * DHCP packet parser and builder.
 */
public class DhcpPacket {
    // DHCP Message Types
    public static final byte DHCP_DISCOVER = 1;
    public static final byte DHCP_OFFER = 2;
    public static final byte DHCP_REQUEST = 3;
    public static final byte DHCP_DECLINE = 4;
    public static final byte DHCP_ACK = 5;
    public static final byte DHCP_NAK = 6;
    public static final byte DHCP_RELEASE = 7;
    public static final byte DHCP_INFORM = 8;

    // DHCP Options
    public static final byte OPTION_SUBNET_MASK = 1;
    public static final byte OPTION_ROUTER = 3;
    public static final byte OPTION_DNS = 6;
    public static final byte OPTION_HOSTNAME = 12;
    public static final byte OPTION_REQUESTED_IP = 50;
    public static final byte OPTION_LEASE_TIME = 51;
    public static final byte OPTION_MESSAGE_TYPE = 53;
    public static final byte OPTION_SERVER_ID = 54;
    public static final byte OPTION_END = (byte) 255;

    // DHCP Magic Cookie
    private static final byte[] MAGIC_COOKIE = {99, (byte) 130, 83, 99};

    // Packet fields
    private byte op;           // Message op code / message type
    private byte htype = 1;    // Hardware address type (Ethernet = 1)
    private byte hlen = 6;     // Hardware address length
    private byte hops = 0;     // Hops
    private int xid;           // Transaction ID
    private short secs = 0;    // Seconds elapsed
    private short flags = 0;   // Flags
    private InetAddress ciaddr; // Client IP address
    private InetAddress yiaddr; // 'Your' (client) IP address
    private InetAddress siaddr; // Next server IP address
    private InetAddress giaddr; // Relay agent IP address
    private byte[] chaddr;      // Client hardware address (MAC)
    private String sname = "";  // Server host name
    private String file = "";   // Boot file name
    private byte[] options;     // DHCP options

    // Parsed option values
    private byte messageType;
    private InetAddress requestedIp;
    private String hostname;

    public DhcpPacket() {
        try {
            ciaddr = InetAddress.getByAddress(new byte[4]);
            yiaddr = InetAddress.getByAddress(new byte[4]);
            siaddr = InetAddress.getByAddress(new byte[4]);
            giaddr = InetAddress.getByAddress(new byte[4]);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
        chaddr = new byte[16];
    }

    /**
     * Parse a DHCP packet from raw bytes.
     */
    public static DhcpPacket parse(byte[] data) throws Exception {
        if (data.length < 240) {
            throw new IllegalArgumentException("Packet too short for DHCP");
        }

        DhcpPacket packet = new DhcpPacket();
        ByteBuffer buffer = ByteBuffer.wrap(data);

        packet.op = buffer.get();
        packet.htype = buffer.get();
        packet.hlen = buffer.get();
        packet.hops = buffer.get();
        packet.xid = buffer.getInt();
        packet.secs = buffer.getShort();
        packet.flags = buffer.getShort();

        byte[] addr = new byte[4];
        buffer.get(addr);
        packet.ciaddr = InetAddress.getByAddress(addr);

        addr = new byte[4];
        buffer.get(addr);
        packet.yiaddr = InetAddress.getByAddress(addr);

        addr = new byte[4];
        buffer.get(addr);
        packet.siaddr = InetAddress.getByAddress(addr);

        addr = new byte[4];
        buffer.get(addr);
        packet.giaddr = InetAddress.getByAddress(addr);

        packet.chaddr = new byte[16];
        buffer.get(packet.chaddr);

        byte[] snameBytes = new byte[64];
        buffer.get(snameBytes);
        packet.sname = new String(snameBytes, StandardCharsets.US_ASCII).trim();

        byte[] fileBytes = new byte[128];
        buffer.get(fileBytes);
        packet.file = new String(fileBytes, StandardCharsets.US_ASCII).trim();

        // Check magic cookie
        byte[] cookie = new byte[4];
        buffer.get(cookie);
        if (!Arrays.equals(cookie, MAGIC_COOKIE)) {
            throw new IllegalArgumentException("Invalid DHCP magic cookie");
        }

        // Parse options
        packet.parseOptions(buffer);

        return packet;
    }

    private void parseOptions(ByteBuffer buffer) throws UnknownHostException {
        while (buffer.hasRemaining()) {
            byte optionCode = buffer.get();
            if (optionCode == OPTION_END || optionCode == 0) {
                break;
            }

            if (!buffer.hasRemaining()) break;
            int length = buffer.get() & 0xFF;
            if (buffer.remaining() < length) break;

            byte[] value = new byte[length];
            buffer.get(value);

            switch (optionCode) {
                case OPTION_MESSAGE_TYPE:
                    if (length >= 1) {
                        messageType = value[0];
                    }
                    break;
                case OPTION_REQUESTED_IP:
                    if (length >= 4) {
                        requestedIp = InetAddress.getByAddress(value);
                    }
                    break;
                case OPTION_HOSTNAME:
                    hostname = new String(value, StandardCharsets.US_ASCII).trim();
                    break;
            }
        }
    }

    /**
     * Build a DHCP response packet.
     */
    public byte[] build() {
        ByteBuffer buffer = ByteBuffer.allocate(576);

        buffer.put(op);
        buffer.put(htype);
        buffer.put(hlen);
        buffer.put(hops);
        buffer.putInt(xid);
        buffer.putShort(secs);
        buffer.putShort(flags);
        buffer.put(ciaddr.getAddress());
        buffer.put(yiaddr.getAddress());
        buffer.put(siaddr.getAddress());
        buffer.put(giaddr.getAddress());
        buffer.put(Arrays.copyOf(chaddr, 16));

        byte[] snameBytes = new byte[64];
        byte[] snameData = sname.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(snameData, 0, snameBytes, 0, Math.min(snameData.length, 64));
        buffer.put(snameBytes);

        byte[] fileBytes = new byte[128];
        byte[] fileData = file.getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(fileData, 0, fileBytes, 0, Math.min(fileData.length, 128));
        buffer.put(fileBytes);

        buffer.put(MAGIC_COOKIE);

        if (options != null) {
            buffer.put(options);
        }
        buffer.put(OPTION_END);

        // Pad to minimum 300 bytes (some clients require this)
        int pos = buffer.position();
        int minSize = 300;
        if (pos < minSize) {
            buffer.put(new byte[minSize - pos]);
            pos = minSize;
        }

        byte[] result = new byte[pos];
        buffer.rewind();
        buffer.get(result);
        return result;
    }

    /**
     * Create a DHCP OFFER response.
     */
    public static DhcpPacket createOffer(DhcpPacket request, InetAddress offeredIp,
                                         InetAddress serverIp, InetAddress gateway,
                                         InetAddress subnetMask, InetAddress dns,
                                         int leaseTime) {
        DhcpPacket offer = new DhcpPacket();
        offer.op = 2; // BOOTREPLY
        offer.htype = request.htype;
        offer.hlen = request.hlen;
        offer.xid = request.xid;
        offer.secs = request.secs;
        offer.flags = request.flags;
        offer.yiaddr = offeredIp;
        offer.siaddr = serverIp;
        offer.giaddr = request.giaddr;
        offer.chaddr = Arrays.copyOf(request.chaddr, 16);

        offer.options = buildOptions(DHCP_OFFER, serverIp, gateway, subnetMask, dns, leaseTime);
        return offer;
    }

    /**
     * Create a DHCP ACK response.
     */
    public static DhcpPacket createAck(DhcpPacket request, InetAddress assignedIp,
                                       InetAddress serverIp, InetAddress gateway,
                                       InetAddress subnetMask, InetAddress dns,
                                       int leaseTime) {
        DhcpPacket ack = new DhcpPacket();
        ack.op = 2; // BOOTREPLY
        ack.htype = request.htype;
        ack.hlen = request.hlen;
        ack.xid = request.xid;
        ack.secs = request.secs;
        ack.flags = request.flags;
        ack.yiaddr = assignedIp;
        ack.siaddr = serverIp;
        ack.giaddr = request.giaddr;
        ack.chaddr = Arrays.copyOf(request.chaddr, 16);

        ack.options = buildOptions(DHCP_ACK, serverIp, gateway, subnetMask, dns, leaseTime);
        return ack;
    }

    /**
     * Create a DHCP NAK response.
     */
    public static DhcpPacket createNak(DhcpPacket request, InetAddress serverIp) {
        DhcpPacket nak = new DhcpPacket();
        nak.op = 2; // BOOTREPLY
        nak.htype = request.htype;
        nak.hlen = request.hlen;
        nak.xid = request.xid;
        nak.flags = request.flags;
        nak.giaddr = request.giaddr;
        nak.chaddr = Arrays.copyOf(request.chaddr, 16);

        ByteBuffer optBuf = ByteBuffer.allocate(16);
        optBuf.put(OPTION_MESSAGE_TYPE);
        optBuf.put((byte) 1);
        optBuf.put(DHCP_NAK);
        optBuf.put(OPTION_SERVER_ID);
        optBuf.put((byte) 4);
        optBuf.put(serverIp.getAddress());

        nak.options = Arrays.copyOf(optBuf.array(), optBuf.position());
        return nak;
    }

    private static byte[] buildOptions(byte messageType, InetAddress serverIp,
                                        InetAddress gateway, InetAddress subnetMask,
                                        InetAddress dns, int leaseTime) {
        ByteBuffer buffer = ByteBuffer.allocate(128);

        // Message type
        buffer.put(OPTION_MESSAGE_TYPE);
        buffer.put((byte) 1);
        buffer.put(messageType);

        // Server identifier
        buffer.put(OPTION_SERVER_ID);
        buffer.put((byte) 4);
        buffer.put(serverIp.getAddress());

        // Lease time
        buffer.put(OPTION_LEASE_TIME);
        buffer.put((byte) 4);
        buffer.putInt(leaseTime);

        // Subnet mask
        buffer.put(OPTION_SUBNET_MASK);
        buffer.put((byte) 4);
        buffer.put(subnetMask.getAddress());

        // Router
        buffer.put(OPTION_ROUTER);
        buffer.put((byte) 4);
        buffer.put(gateway.getAddress());

        // DNS
        buffer.put(OPTION_DNS);
        buffer.put((byte) 4);
        buffer.put(dns.getAddress());

        byte[] result = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(result);
        return result;
    }

    // Getters
    public byte getOp() { return op; }
    public int getXid() { return xid; }
    public byte[] getChaddr() { return chaddr; }
    public InetAddress getCiaddr() { return ciaddr; }
    public byte getMessageType() { return messageType; }
    public InetAddress getRequestedIp() { return requestedIp; }
    public String getHostname() { return hostname; }

    public String getMacAddressString() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02X", chaddr[i] & 0xFF));
        }
        return sb.toString();
    }

    public static String messageTypeName(byte type) {
        return switch (type) {
            case DHCP_DISCOVER -> "DISCOVER";
            case DHCP_OFFER -> "OFFER";
            case DHCP_REQUEST -> "REQUEST";
            case DHCP_DECLINE -> "DECLINE";
            case DHCP_ACK -> "ACK";
            case DHCP_NAK -> "NAK";
            case DHCP_RELEASE -> "RELEASE";
            case DHCP_INFORM -> "INFORM";
            default -> "UNKNOWN(" + type + ")";
        };
    }
}
