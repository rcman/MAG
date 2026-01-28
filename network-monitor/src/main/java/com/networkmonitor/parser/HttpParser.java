package com.networkmonitor.parser;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parser for HTTP packets.
 */
public class HttpParser {
    private static final Logger logger = LoggerFactory.getLogger(HttpParser.class);

    // HTTP request line pattern: METHOD URI HTTP/VERSION
    private static final Pattern REQUEST_PATTERN = Pattern.compile(
            "^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\\s+(\\S+)\\s+HTTP/(\\d\\.\\d)",
            Pattern.MULTILINE
    );

    // HTTP response status line pattern: HTTP/VERSION STATUS MESSAGE
    private static final Pattern RESPONSE_PATTERN = Pattern.compile(
            "^HTTP/(\\d\\.\\d)\\s+(\\d{3})\\s+(.*?)\\r?$",
            Pattern.MULTILINE
    );

    // Host header pattern
    private static final Pattern HOST_PATTERN = Pattern.compile(
            "^Host:\\s*(\\S+)",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE
    );

    // Content-Type header pattern
    private static final Pattern CONTENT_TYPE_PATTERN = Pattern.compile(
            "^Content-Type:\\s*([^\\r\\n;]+)",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE
    );

    // Content-Length header pattern
    private static final Pattern CONTENT_LENGTH_PATTERN = Pattern.compile(
            "^Content-Length:\\s*(\\d+)",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE
    );

    // User-Agent header pattern
    private static final Pattern USER_AGENT_PATTERN = Pattern.compile(
            "^User-Agent:\\s*([^\\r\\n]+)",
            Pattern.MULTILINE | Pattern.CASE_INSENSITIVE
    );

    public String parse(byte[] data, String srcIp, int srcPort, String dstIp, int dstPort) {
        try {
            // Try to interpret as text
            String text = new String(data, StandardCharsets.ISO_8859_1);

            // Check for HTTP request
            Matcher requestMatcher = REQUEST_PATTERN.matcher(text);
            if (requestMatcher.find()) {
                return parseRequest(text, requestMatcher, srcIp, srcPort, dstIp, dstPort);
            }

            // Check for HTTP response
            Matcher responseMatcher = RESPONSE_PATTERN.matcher(text);
            if (responseMatcher.find()) {
                return parseResponse(text, responseMatcher, srcIp, srcPort, dstIp, dstPort);
            }

            return null;

        } catch (Exception e) {
            logger.debug("Error parsing HTTP packet: {}", e.getMessage());
            return null;
        }
    }

    private String parseRequest(String text, Matcher requestMatcher,
                                 String srcIp, int srcPort, String dstIp, int dstPort) {
        String method = requestMatcher.group(1);
        String uri = requestMatcher.group(2);
        String version = requestMatcher.group(3);

        StringBuilder result = new StringBuilder();
        result.append("HTTP ").append(method).append(" | ");
        result.append(srcIp).append(":").append(srcPort);
        result.append(" -> ").append(dstIp).append(":").append(dstPort);

        // Extract host
        Matcher hostMatcher = HOST_PATTERN.matcher(text);
        if (hostMatcher.find()) {
            result.append(" | Host: ").append(hostMatcher.group(1));
        }

        result.append(" | ").append(uri);

        // Extract User-Agent (truncated)
        Matcher uaMatcher = USER_AGENT_PATTERN.matcher(text);
        if (uaMatcher.find()) {
            String ua = uaMatcher.group(1);
            if (ua.length() > 50) {
                ua = ua.substring(0, 47) + "...";
            }
            result.append(" | UA: ").append(ua);
        }

        return result.toString();
    }

    private String parseResponse(String text, Matcher responseMatcher,
                                  String srcIp, int srcPort, String dstIp, int dstPort) {
        String version = responseMatcher.group(1);
        String statusCode = responseMatcher.group(2);
        String statusMessage = responseMatcher.group(3).trim();

        StringBuilder result = new StringBuilder();
        result.append("HTTP RESPONSE | ");
        result.append(srcIp).append(":").append(srcPort);
        result.append(" -> ").append(dstIp).append(":").append(dstPort);
        result.append(" | ").append(statusCode).append(" ").append(statusMessage);

        // Extract Content-Type
        Matcher ctMatcher = CONTENT_TYPE_PATTERN.matcher(text);
        if (ctMatcher.find()) {
            result.append(" | Type: ").append(ctMatcher.group(1).trim());
        }

        // Extract Content-Length
        Matcher clMatcher = CONTENT_LENGTH_PATTERN.matcher(text);
        if (clMatcher.find()) {
            result.append(" | Size: ").append(clMatcher.group(1)).append("B");
        }

        return result.toString();
    }
}
