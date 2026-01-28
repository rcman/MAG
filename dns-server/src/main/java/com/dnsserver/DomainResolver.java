package com.dnsserver;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Pattern;

public class DomainResolver {
    private static final Logger logger = LoggerFactory.getLogger(DomainResolver.class);

    private String serverIp = "10.0.0.1";
    private String upstreamDns = "8.8.8.8";
    private final Map<String, String> exactDomains = new HashMap<>();
    private final List<WildcardEntry> wildcardDomains = new ArrayList<>();

    private static class WildcardEntry {
        Pattern pattern;
        String ip;

        WildcardEntry(String wildcard, String ip) {
            // Convert wildcard pattern to regex
            // *.example.com -> .*\.example\.com
            String regex = wildcard
                    .replace(".", "\\.")
                    .replace("*", ".*");
            this.pattern = Pattern.compile("^" + regex + "$", Pattern.CASE_INSENSITIVE);
            this.ip = ip;
        }

        boolean matches(String domain) {
            return pattern.matcher(domain).matches();
        }
    }

    public void loadConfig(String configPath) {
        Properties props = new Properties();

        // Try loading from file first
        Path path = Path.of(configPath);
        if (Files.exists(path)) {
            try (InputStream is = Files.newInputStream(path)) {
                props.load(is);
                logger.info("Loaded domain configuration from {}", configPath);
            } catch (IOException e) {
                logger.error("Error loading config from file: {}", e.getMessage());
                loadDefaultConfig(props);
            }
        } else {
            // Try loading from classpath
            try (InputStream is = getClass().getResourceAsStream("/domains.properties")) {
                if (is != null) {
                    props.load(is);
                    logger.info("Loaded domain configuration from classpath");
                } else {
                    loadDefaultConfig(props);
                }
            } catch (IOException e) {
                logger.error("Error loading config from classpath: {}", e.getMessage());
                loadDefaultConfig(props);
            }
        }

        parseProperties(props);
    }

    private void loadDefaultConfig(Properties props) {
        logger.info("Using default PlayStation domain configuration");
        props.setProperty("server.ip", "10.0.0.1");
        props.setProperty("upstream.dns", "8.8.8.8");
        props.setProperty("*.playstation.net", "${server.ip}");
        props.setProperty("*.playstation.com", "${server.ip}");
        props.setProperty("*.playstation.org", "${server.ip}");
        props.setProperty("*.sonyentertainmentnetwork.com", "${server.ip}");
    }

    private void parseProperties(Properties props) {
        // First, get server.ip and upstream.dns
        serverIp = props.getProperty("server.ip", "10.0.0.1");
        upstreamDns = props.getProperty("upstream.dns", "8.8.8.8");

        logger.info("Server IP: {}", serverIp);
        logger.info("Upstream DNS: {}", upstreamDns);

        // Parse domain mappings
        for (String key : props.stringPropertyNames()) {
            if (key.equals("server.ip") || key.equals("upstream.dns")) {
                continue;
            }

            String value = props.getProperty(key);
            // Replace ${server.ip} placeholder
            value = value.replace("${server.ip}", serverIp);

            if (key.contains("*")) {
                wildcardDomains.add(new WildcardEntry(key, value));
                logger.debug("Added wildcard domain: {} -> {}", key, value);
            } else {
                exactDomains.put(key.toLowerCase(), value);
                logger.debug("Added exact domain: {} -> {}", key, value);
            }
        }

        logger.info("Loaded {} exact domains and {} wildcard patterns",
                exactDomains.size(), wildcardDomains.size());
    }

    public String resolve(String domain) {
        String lowerDomain = domain.toLowerCase();

        // Check exact match first
        String ip = exactDomains.get(lowerDomain);
        if (ip != null) {
            logger.debug("Exact match for {}: {}", domain, ip);
            return ip;
        }

        // Check wildcard patterns
        for (WildcardEntry entry : wildcardDomains) {
            if (entry.matches(lowerDomain)) {
                logger.debug("Wildcard match for {}: {}", domain, entry.ip);
                return entry.ip;
            }
        }

        logger.debug("No match for domain: {}", domain);
        return null;
    }

    public String getServerIp() {
        return serverIp;
    }

    public void setServerIp(String serverIp) {
        this.serverIp = serverIp;
    }

    public String getUpstreamDns() {
        return upstreamDns;
    }

    public void setUpstreamDns(String upstreamDns) {
        this.upstreamDns = upstreamDns;
    }

    public void addDomain(String domain, String ip) {
        if (domain.contains("*")) {
            wildcardDomains.add(new WildcardEntry(domain, ip));
        } else {
            exactDomains.put(domain.toLowerCase(), ip);
        }
    }

    public Set<String> getConfiguredDomains() {
        Set<String> domains = new HashSet<>(exactDomains.keySet());
        for (WildcardEntry entry : wildcardDomains) {
            domains.add(entry.pattern.pattern());
        }
        return domains;
    }
}
