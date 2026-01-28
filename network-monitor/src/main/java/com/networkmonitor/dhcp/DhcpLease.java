package com.networkmonitor.dhcp;

import java.net.InetAddress;
import java.time.Instant;

/**
 * Represents a DHCP lease for a client.
 */
public class DhcpLease {
    private final String macAddress;
    private final InetAddress ipAddress;
    private final Instant leaseStart;
    private final Instant leaseExpiry;
    private String hostname;

    public DhcpLease(String macAddress, InetAddress ipAddress, long leaseSeconds) {
        this.macAddress = macAddress;
        this.ipAddress = ipAddress;
        this.leaseStart = Instant.now();
        this.leaseExpiry = leaseStart.plusSeconds(leaseSeconds);
    }

    public String getMacAddress() {
        return macAddress;
    }

    public InetAddress getIpAddress() {
        return ipAddress;
    }

    public Instant getLeaseStart() {
        return leaseStart;
    }

    public Instant getLeaseExpiry() {
        return leaseExpiry;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(leaseExpiry);
    }

    public long getRemainingSeconds() {
        long remaining = leaseExpiry.getEpochSecond() - Instant.now().getEpochSecond();
        return Math.max(0, remaining);
    }

    @Override
    public String toString() {
        return String.format("DhcpLease[mac=%s, ip=%s, hostname=%s, expires=%s]",
                macAddress, ipAddress.getHostAddress(), hostname, leaseExpiry);
    }
}
