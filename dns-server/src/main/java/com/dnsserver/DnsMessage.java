package com.dnsserver;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class DnsMessage {

    // DNS Header fields
    private int id;
    private int flags;
    private int questionCount;
    private int answerCount;
    private int authorityCount;
    private int additionalCount;

    // Questions
    private List<DnsQuestion> questions = new ArrayList<>();

    // Query types
    public static final int TYPE_A = 1;      // IPv4 address
    public static final int TYPE_AAAA = 28;  // IPv6 address
    public static final int TYPE_CNAME = 5;  // Canonical name
    public static final int TYPE_PTR = 12;   // Pointer
    public static final int TYPE_MX = 15;    // Mail exchange
    public static final int TYPE_TXT = 16;   // Text record
    public static final int TYPE_SOA = 6;    // Start of authority
    public static final int TYPE_NS = 2;     // Name server

    // Query classes
    public static final int CLASS_IN = 1;    // Internet

    // Response codes
    public static final int RCODE_OK = 0;
    public static final int RCODE_FORMAT_ERROR = 1;
    public static final int RCODE_SERVER_FAILURE = 2;
    public static final int RCODE_NAME_ERROR = 3;  // NXDOMAIN
    public static final int RCODE_NOT_IMPLEMENTED = 4;
    public static final int RCODE_REFUSED = 5;

    public static class DnsQuestion {
        public String name;
        public int type;
        public int qclass;

        public DnsQuestion(String name, int type, int qclass) {
            this.name = name;
            this.type = type;
            this.qclass = qclass;
        }

        public String getTypeString() {
            return switch (type) {
                case TYPE_A -> "A";
                case TYPE_AAAA -> "AAAA";
                case TYPE_CNAME -> "CNAME";
                case TYPE_PTR -> "PTR";
                case TYPE_MX -> "MX";
                case TYPE_TXT -> "TXT";
                case TYPE_SOA -> "SOA";
                case TYPE_NS -> "NS";
                default -> "TYPE" + type;
            };
        }
    }

    public static DnsMessage parse(byte[] data) throws IOException {
        DnsMessage msg = new DnsMessage();
        ByteBuffer buffer = ByteBuffer.wrap(data);

        // Parse header
        msg.id = buffer.getShort() & 0xFFFF;
        msg.flags = buffer.getShort() & 0xFFFF;
        msg.questionCount = buffer.getShort() & 0xFFFF;
        msg.answerCount = buffer.getShort() & 0xFFFF;
        msg.authorityCount = buffer.getShort() & 0xFFFF;
        msg.additionalCount = buffer.getShort() & 0xFFFF;

        // Parse questions
        for (int i = 0; i < msg.questionCount; i++) {
            String name = parseDomainName(buffer, data);
            int type = buffer.getShort() & 0xFFFF;
            int qclass = buffer.getShort() & 0xFFFF;
            msg.questions.add(new DnsQuestion(name, type, qclass));
        }

        return msg;
    }

    private static String parseDomainName(ByteBuffer buffer, byte[] data) {
        StringBuilder name = new StringBuilder();
        int length;

        while ((length = buffer.get() & 0xFF) != 0) {
            // Check for compression pointer
            if ((length & 0xC0) == 0xC0) {
                int pointer = ((length & 0x3F) << 8) | (buffer.get() & 0xFF);
                ByteBuffer pointerBuffer = ByteBuffer.wrap(data);
                pointerBuffer.position(pointer);
                if (name.length() > 0) {
                    name.append(".");
                }
                name.append(parseDomainName(pointerBuffer, data));
                return name.toString();
            }

            if (name.length() > 0) {
                name.append(".");
            }

            byte[] labelBytes = new byte[length];
            buffer.get(labelBytes);
            name.append(new String(labelBytes, StandardCharsets.UTF_8));
        }

        return name.toString();
    }

    public byte[] buildResponse(String ipAddress, int ttl) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Write header
        dos.writeShort(id);

        // Flags: QR=1 (response), Opcode=0, AA=1, TC=0, RD=1, RA=1, Z=0, RCODE=0
        int responseFlags = 0x8580; // Standard query response, authoritative
        dos.writeShort(responseFlags);

        // Question count
        dos.writeShort(questions.size());

        // Answer count (one for each A query with an IP)
        int answers = 0;
        if (ipAddress != null) {
            for (DnsQuestion q : questions) {
                if (q.type == TYPE_A) answers++;
            }
        }
        dos.writeShort(answers);

        // Authority and additional counts
        dos.writeShort(0);
        dos.writeShort(0);

        // Write questions
        for (DnsQuestion q : questions) {
            writeDomainName(dos, q.name);
            dos.writeShort(q.type);
            dos.writeShort(q.qclass);
        }

        // Write answers for A records
        if (ipAddress != null) {
            for (DnsQuestion q : questions) {
                if (q.type == TYPE_A) {
                    writeDomainName(dos, q.name);
                    dos.writeShort(TYPE_A);
                    dos.writeShort(CLASS_IN);
                    dos.writeInt(ttl);
                    dos.writeShort(4); // Length of IPv4 address

                    // Write IP address
                    String[] parts = ipAddress.split("\\.");
                    for (String part : parts) {
                        dos.writeByte(Integer.parseInt(part));
                    }
                }
            }
        }

        return baos.toByteArray();
    }

    public byte[] buildNxdomainResponse() throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        // Write header
        dos.writeShort(id);

        // Flags: QR=1, RCODE=3 (NXDOMAIN)
        int responseFlags = 0x8183;
        dos.writeShort(responseFlags);

        dos.writeShort(questions.size());
        dos.writeShort(0); // No answers
        dos.writeShort(0); // No authority
        dos.writeShort(0); // No additional

        // Write questions
        for (DnsQuestion q : questions) {
            writeDomainName(dos, q.name);
            dos.writeShort(q.type);
            dos.writeShort(q.qclass);
        }

        return baos.toByteArray();
    }

    private void writeDomainName(DataOutputStream dos, String name) throws IOException {
        String[] labels = name.split("\\.");
        for (String label : labels) {
            byte[] bytes = label.getBytes(StandardCharsets.UTF_8);
            dos.writeByte(bytes.length);
            dos.write(bytes);
        }
        dos.writeByte(0); // End of name
    }

    // Getters
    public int getId() { return id; }
    public int getFlags() { return flags; }
    public List<DnsQuestion> getQuestions() { return questions; }

    public boolean isQuery() {
        return (flags & 0x8000) == 0;
    }

    public int getOpcode() {
        return (flags >> 11) & 0x0F;
    }
}
