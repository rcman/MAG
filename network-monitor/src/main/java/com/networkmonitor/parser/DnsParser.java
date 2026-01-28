package com.networkmonitor.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Parser for DNS packets.
 */
public class DnsParser {
    private static final Logger logger = LoggerFactory.getLogger(DnsParser.class);

    // DNS record types
    private static final int TYPE_A = 1;
    private static final int TYPE_AAAA = 28;
    private static final int TYPE_CNAME = 5;
    private static final int TYPE_MX = 15;
    private static final int TYPE_TXT = 16;
    private static final int TYPE_NS = 2;
    private static final int TYPE_PTR = 12;

    public String parse(byte[] data, String srcIp, String dstIp) {
        try {
            if (data.length < 12) {
                return null;
            }

            ByteBuffer buffer = ByteBuffer.wrap(data);

            // DNS header
            int transactionId = buffer.getShort() & 0xFFFF;
            int flags = buffer.getShort() & 0xFFFF;
            int questions = buffer.getShort() & 0xFFFF;
            int answers = buffer.getShort() & 0xFFFF;
            int authority = buffer.getShort() & 0xFFFF;
            int additional = buffer.getShort() & 0xFFFF;

            boolean isResponse = (flags & 0x8000) != 0;
            int opcode = (flags >> 11) & 0x0F;
            int rcode = flags & 0x0F;

            StringBuilder result = new StringBuilder();

            if (isResponse) {
                result.append("DNS RESPONSE | ");
                result.append(srcIp).append(" -> ").append(dstIp);

                // Parse questions to get the query name
                List<String> queryNames = new ArrayList<>();
                for (int i = 0; i < questions && buffer.hasRemaining(); i++) {
                    String name = readDomainName(buffer, data);
                    if (name != null) {
                        int type = buffer.getShort() & 0xFFFF;
                        int clazz = buffer.getShort() & 0xFFFF;
                        queryNames.add(name + " (" + getTypeName(type) + ")");
                    }
                }

                if (!queryNames.isEmpty()) {
                    result.append(" | Query: ").append(String.join(", ", queryNames));
                }

                // Parse answer records
                List<String> answerStrs = new ArrayList<>();
                for (int i = 0; i < answers && buffer.hasRemaining(); i++) {
                    String answer = parseResourceRecord(buffer, data);
                    if (answer != null) {
                        answerStrs.add(answer);
                    }
                }

                if (!answerStrs.isEmpty()) {
                    result.append(" | Answers: ").append(String.join(", ", answerStrs));
                }

                if (rcode != 0) {
                    result.append(" | Error: ").append(getRcodeName(rcode));
                }

            } else {
                result.append("DNS QUERY | ");
                result.append(srcIp).append(" -> ").append(dstIp);

                // Parse questions
                List<String> queries = new ArrayList<>();
                for (int i = 0; i < questions && buffer.hasRemaining(); i++) {
                    String name = readDomainName(buffer, data);
                    if (name != null && buffer.remaining() >= 4) {
                        int type = buffer.getShort() & 0xFFFF;
                        int clazz = buffer.getShort() & 0xFFFF;
                        queries.add(name + " (" + getTypeName(type) + ")");
                    }
                }

                if (!queries.isEmpty()) {
                    result.append(" | ").append(String.join(", ", queries));
                }
            }

            return result.toString();

        } catch (Exception e) {
            logger.debug("Error parsing DNS packet: {}", e.getMessage());
            return null;
        }
    }

    private String readDomainName(ByteBuffer buffer, byte[] data) {
        StringBuilder name = new StringBuilder();
        int maxJumps = 10;
        int jumps = 0;
        int savedPosition = -1;

        while (buffer.hasRemaining() && jumps < maxJumps) {
            int length = buffer.get() & 0xFF;

            if (length == 0) {
                break;
            }

            // Check for compression pointer
            if ((length & 0xC0) == 0xC0) {
                if (!buffer.hasRemaining()) break;
                int offset = ((length & 0x3F) << 8) | (buffer.get() & 0xFF);
                if (savedPosition == -1) {
                    savedPosition = buffer.position();
                }
                buffer.position(offset);
                jumps++;
                continue;
            }

            if (buffer.remaining() < length) break;

            byte[] label = new byte[length];
            buffer.get(label);

            if (name.length() > 0) {
                name.append(".");
            }
            name.append(new String(label, StandardCharsets.UTF_8));
        }

        if (savedPosition != -1) {
            buffer.position(savedPosition);
        }

        return name.length() > 0 ? name.toString() : null;
    }

    private String parseResourceRecord(ByteBuffer buffer, byte[] data) {
        try {
            String name = readDomainName(buffer, data);
            if (name == null || buffer.remaining() < 10) return null;

            int type = buffer.getShort() & 0xFFFF;
            int clazz = buffer.getShort() & 0xFFFF;
            int ttl = buffer.getInt();
            int rdLength = buffer.getShort() & 0xFFFF;

            if (buffer.remaining() < rdLength) return null;

            String value = null;
            switch (type) {
                case TYPE_A:
                    if (rdLength == 4) {
                        byte[] addr = new byte[4];
                        buffer.get(addr);
                        value = InetAddress.getByAddress(addr).getHostAddress();
                    } else {
                        buffer.position(buffer.position() + rdLength);
                    }
                    break;
                case TYPE_AAAA:
                    if (rdLength == 16) {
                        byte[] addr = new byte[16];
                        buffer.get(addr);
                        value = InetAddress.getByAddress(addr).getHostAddress();
                    } else {
                        buffer.position(buffer.position() + rdLength);
                    }
                    break;
                case TYPE_CNAME:
                case TYPE_NS:
                case TYPE_PTR:
                    int startPos = buffer.position();
                    value = readDomainName(buffer, data);
                    // Ensure we've consumed exactly rdLength bytes
                    buffer.position(startPos + rdLength);
                    break;
                default:
                    buffer.position(buffer.position() + rdLength);
                    break;
            }

            if (value != null) {
                return value;
            }
            return null;

        } catch (Exception e) {
            return null;
        }
    }

    private String getTypeName(int type) {
        return switch (type) {
            case TYPE_A -> "A";
            case TYPE_AAAA -> "AAAA";
            case TYPE_CNAME -> "CNAME";
            case TYPE_MX -> "MX";
            case TYPE_TXT -> "TXT";
            case TYPE_NS -> "NS";
            case TYPE_PTR -> "PTR";
            default -> "TYPE" + type;
        };
    }

    private String getRcodeName(int rcode) {
        return switch (rcode) {
            case 0 -> "NOERROR";
            case 1 -> "FORMERR";
            case 2 -> "SERVFAIL";
            case 3 -> "NXDOMAIN";
            case 4 -> "NOTIMP";
            case 5 -> "REFUSED";
            default -> "RCODE" + rcode;
        };
    }
}
