package com.networkmonitor.capture;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Wrapper for pcap4j packet capture functionality.
 */
public class PacketCapture {
    private static final Logger logger = LoggerFactory.getLogger(PacketCapture.class);

    private static final int SNAPSHOT_LENGTH = 65536;
    private static final int READ_TIMEOUT = 50; // milliseconds

    private PcapHandle handle;
    private PcapNetworkInterface networkInterface;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread captureThread;
    private PacketHandler packetHandler;

    public PacketCapture() {
    }

    /**
     * Get list of available network interfaces.
     */
    public static List<PcapNetworkInterface> getNetworkInterfaces() {
        try {
            return Pcaps.findAllDevs();
        } catch (PcapNativeException e) {
            logger.error("Failed to get network interfaces", e);
            return new ArrayList<>();
        }
    }

    /**
     * Get a network interface by name.
     */
    public static PcapNetworkInterface getInterfaceByName(String name) {
        try {
            return Pcaps.getDevByName(name);
        } catch (PcapNativeException e) {
            logger.error("Failed to get interface: {}", name, e);
            return null;
        }
    }

    /**
     * Auto-detect a suitable network interface.
     */
    public static PcapNetworkInterface autoDetectInterface() {
        List<PcapNetworkInterface> interfaces = getNetworkInterfaces();

        for (PcapNetworkInterface nif : interfaces) {
            // Skip loopback and interfaces without addresses
            if (nif.isLoopBack()) continue;
            if (nif.getAddresses().isEmpty()) continue;

            // Prefer interfaces with IPv4 addresses
            for (PcapAddress addr : nif.getAddresses()) {
                if (addr.getAddress() != null &&
                    addr.getAddress().getHostAddress().startsWith("10.0.0.")) {
                    logger.info("Auto-detected interface: {} ({})",
                            nif.getName(), nif.getDescription());
                    return nif;
                }
            }
        }

        // Fall back to first non-loopback interface with an address
        for (PcapNetworkInterface nif : interfaces) {
            if (!nif.isLoopBack() && !nif.getAddresses().isEmpty()) {
                logger.info("Using interface: {} ({})", nif.getName(), nif.getDescription());
                return nif;
            }
        }

        return null;
    }

    public void setNetworkInterface(PcapNetworkInterface networkInterface) {
        this.networkInterface = networkInterface;
    }

    public void setPacketHandler(PacketHandler handler) {
        this.packetHandler = handler;
    }

    public void start() throws PcapNativeException, NotOpenException {
        if (networkInterface == null) {
            throw new IllegalStateException("No network interface selected");
        }

        if (packetHandler == null) {
            throw new IllegalStateException("No packet handler set");
        }

        if (running.get()) {
            logger.warn("Packet capture already running");
            return;
        }

        // Open the interface in promiscuous mode
        handle = networkInterface.openLive(
                SNAPSHOT_LENGTH,
                PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                READ_TIMEOUT
        );

        logger.info("Opened interface {} for capture", networkInterface.getName());

        running.set(true);
        captureThread = new Thread(this::captureLoop, "Packet-Capture");
        captureThread.setDaemon(true);
        captureThread.start();

        logger.info("Packet capture started on {}", networkInterface.getName());
    }

    public void stop() {
        running.set(false);

        if (captureThread != null) {
            captureThread.interrupt();
            try {
                captureThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        if (handle != null && handle.isOpen()) {
            try {
                handle.breakLoop();
            } catch (NotOpenException e) {
                // Ignore
            }
            handle.close();
        }

        logger.info("Packet capture stopped");
    }

    public boolean isRunning() {
        return running.get();
    }

    private void captureLoop() {
        try {
            while (running.get()) {
                Packet packet = handle.getNextPacket();
                if (packet != null) {
                    packetHandler.handlePacket(packet);
                }
            }
        } catch (NotOpenException e) {
            if (running.get()) {
                logger.error("Capture handle closed unexpectedly", e);
            }
        } catch (Exception e) {
            if (running.get()) {
                logger.error("Error in capture loop", e);
            }
        }
    }

    public PcapNetworkInterface getNetworkInterface() {
        return networkInterface;
    }

    public PcapHandle getHandle() {
        return handle;
    }

    /**
     * Get interface information as a displayable string.
     */
    public static String getInterfaceInfo(PcapNetworkInterface nif) {
        StringBuilder sb = new StringBuilder();
        sb.append(nif.getName());
        if (nif.getDescription() != null && !nif.getDescription().isEmpty()) {
            sb.append(" (").append(nif.getDescription()).append(")");
        }

        if (!nif.getAddresses().isEmpty()) {
            sb.append(" - ");
            boolean first = true;
            for (PcapAddress addr : nif.getAddresses()) {
                if (addr.getAddress() != null) {
                    if (!first) sb.append(", ");
                    sb.append(addr.getAddress().getHostAddress());
                    first = false;
                }
            }
        }

        return sb.toString();
    }
}
