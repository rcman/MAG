package com.networkmonitor;

import com.networkmonitor.gui.MonitorDashboard;
import com.networkmonitor.logging.TrafficLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * Main entry point for the Network Traffic Monitor application.
 */
public class NetworkMonitor {
    private static final Logger logger = LoggerFactory.getLogger(NetworkMonitor.class);

    public static void main(String[] args) {
        logger.info("Starting Network Traffic Monitor");

        // Set system look and feel
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception e) {
            logger.warn("Could not set system look and feel", e);
        }

        // Load configuration
        Properties config = loadConfig();

        // Initialize traffic logger
        TrafficLogger trafficLogger;
        try {
            String logDir = config.getProperty("log.directory", "./logs");
            trafficLogger = new TrafficLogger(logDir);
            trafficLogger.start();
        } catch (IOException e) {
            logger.error("Failed to initialize traffic logger", e);
            JOptionPane.showMessageDialog(null,
                    "Failed to initialize logging: " + e.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Create and show GUI
        SwingUtilities.invokeLater(() -> {
            MonitorDashboard dashboard = new MonitorDashboard(config, trafficLogger);
            dashboard.setVisible(true);
        });
    }

    private static Properties loadConfig() {
        Properties config = new Properties();

        // Set defaults
        config.setProperty("network.interface", "auto");
        config.setProperty("dhcp.enabled", "true");
        config.setProperty("dhcp.range.start", "10.0.0.10");
        config.setProperty("dhcp.range.end", "10.0.0.200");
        config.setProperty("dhcp.gateway", "10.0.0.1");
        config.setProperty("dhcp.netmask", "255.255.255.0");
        config.setProperty("dhcp.lease.hours", "24");
        config.setProperty("dhcp.dns", "8.8.8.8");
        config.setProperty("log.directory", "./logs");
        config.setProperty("log.max.entries.display", "100");

        // Try to load from file
        try (InputStream is = NetworkMonitor.class.getClassLoader()
                .getResourceAsStream("config.properties")) {
            if (is != null) {
                config.load(is);
                logger.info("Loaded configuration from config.properties");
            }
        } catch (IOException e) {
            logger.warn("Could not load config.properties, using defaults", e);
        }

        return config;
    }
}
