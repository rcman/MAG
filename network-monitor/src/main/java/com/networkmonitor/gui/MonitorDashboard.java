package com.networkmonitor.gui;

import com.networkmonitor.capture.PacketCapture;
import com.networkmonitor.capture.PacketHandler;
import com.networkmonitor.dhcp.DhcpLease;
import com.networkmonitor.dhcp.DhcpServer;
import com.networkmonitor.logging.TrafficLogger;
import org.pcap4j.core.PcapNetworkInterface;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.time.format.DateTimeFormatter;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;

/**
 * Swing GUI Dashboard for the Network Traffic Monitor.
 */
public class MonitorDashboard extends JFrame {
    private static final Logger logger = LoggerFactory.getLogger(MonitorDashboard.class);
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");

    // Configuration
    private final Properties config;
    private final int maxDisplayEntries;

    // Components
    private final PacketCapture packetCapture;
    private final PacketHandler packetHandler;
    private final TrafficLogger trafficLogger;
    private DhcpServer dhcpServer;

    // GUI Components
    private JComboBox<InterfaceItem> interfaceSelector;
    private JButton startButton;
    private JButton stopButton;
    private JTable trafficTable;
    private DefaultTableModel trafficTableModel;
    private JTable clientsTable;
    private DefaultTableModel clientsTableModel;
    private JLabel statusLabel;
    private JLabel packetCountLabel;
    private JLabel tcpCountLabel;
    private JLabel udpCountLabel;
    private JLabel dnsCountLabel;
    private JLabel httpCountLabel;
    private JLabel dhcpStatusLabel;
    private JLabel logFileLabel;

    // Update timer
    private Timer statsUpdateTimer;

    public MonitorDashboard(Properties config, TrafficLogger trafficLogger) {
        this.config = config;
        this.trafficLogger = trafficLogger;
        this.maxDisplayEntries = Integer.parseInt(config.getProperty("log.max.entries.display", "100"));

        this.packetCapture = new PacketCapture();
        this.packetHandler = new PacketHandler(trafficLogger);

        initializeGUI();
        populateInterfaces();
        startStatsTimer();
    }

    private void initializeGUI() {
        setTitle("Network Traffic Monitor");
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        setSize(1200, 800);
        setLocationRelativeTo(null);

        // Handle window close
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                shutdown();
                dispose();
                System.exit(0);
            }
        });

        // Main layout
        setLayout(new BorderLayout(5, 5));

        // Top panel - Controls
        add(createControlPanel(), BorderLayout.NORTH);

        // Center - Split pane with traffic and clients
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.7);
        splitPane.setLeftComponent(createTrafficPanel());
        splitPane.setRightComponent(createClientsPanel());
        add(splitPane, BorderLayout.CENTER);

        // Bottom panel - Statistics
        add(createStatsPanel(), BorderLayout.SOUTH);
    }

    private JPanel createControlPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        panel.setBorder(BorderFactory.createTitledBorder("Controls"));

        // Interface selector
        panel.add(new JLabel("Interface:"));
        interfaceSelector = new JComboBox<>();
        interfaceSelector.setPreferredSize(new Dimension(400, 25));
        panel.add(interfaceSelector);

        // Start button
        startButton = new JButton("Start Monitoring");
        startButton.setBackground(new Color(76, 175, 80));
        startButton.addActionListener(e -> startMonitoring());
        panel.add(startButton);

        // Stop button
        stopButton = new JButton("Stop Monitoring");
        stopButton.setBackground(new Color(244, 67, 54));
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopMonitoring());
        panel.add(stopButton);

        // Status label
        statusLabel = new JLabel("Status: Stopped");
        statusLabel.setFont(statusLabel.getFont().deriveFont(Font.BOLD));
        panel.add(Box.createHorizontalStrut(20));
        panel.add(statusLabel);

        return panel;
    }

    private JPanel createTrafficPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("Live Traffic"));

        // Traffic table
        String[] columns = {"Time", "Protocol", "Source", "Destination", "Details"};
        trafficTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        trafficTable = new JTable(trafficTableModel);
        trafficTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        trafficTable.getColumnModel().getColumn(0).setPreferredWidth(80);
        trafficTable.getColumnModel().getColumn(1).setPreferredWidth(80);
        trafficTable.getColumnModel().getColumn(2).setPreferredWidth(150);
        trafficTable.getColumnModel().getColumn(3).setPreferredWidth(150);
        trafficTable.getColumnModel().getColumn(4).setPreferredWidth(300);

        JScrollPane scrollPane = new JScrollPane(trafficTable);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        panel.add(scrollPane, BorderLayout.CENTER);

        // Clear button
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            trafficTableModel.setRowCount(0);
        });
        buttonPanel.add(clearButton);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createClientsPanel() {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder("Connected Clients (DHCP Leases)"));

        // Clients table
        String[] columns = {"MAC Address", "IP Address", "Hostname", "Lease Time"};
        clientsTableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        clientsTable = new JTable(clientsTableModel);
        clientsTable.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        JScrollPane scrollPane = new JScrollPane(clientsTable);
        panel.add(scrollPane, BorderLayout.CENTER);

        // DHCP status
        dhcpStatusLabel = new JLabel("DHCP: Not started");
        panel.add(dhcpStatusLabel, BorderLayout.SOUTH);

        return panel;
    }

    private JPanel createStatsPanel() {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT, 20, 5));
        panel.setBorder(BorderFactory.createTitledBorder("Statistics"));

        packetCountLabel = new JLabel("Packets: 0");
        tcpCountLabel = new JLabel("TCP: 0");
        udpCountLabel = new JLabel("UDP: 0");
        dnsCountLabel = new JLabel("DNS: 0");
        httpCountLabel = new JLabel("HTTP: 0");
        logFileLabel = new JLabel("Log: -");

        panel.add(packetCountLabel);
        panel.add(tcpCountLabel);
        panel.add(udpCountLabel);
        panel.add(dnsCountLabel);
        panel.add(httpCountLabel);
        panel.add(Box.createHorizontalStrut(50));
        panel.add(logFileLabel);

        return panel;
    }

    private void populateInterfaces() {
        List<PcapNetworkInterface> interfaces = PacketCapture.getNetworkInterfaces();

        interfaceSelector.removeAllItems();

        for (PcapNetworkInterface nif : interfaces) {
            // Only show Ethernet interfaces (skip loopback, WiFi, virtual interfaces)
            String name = nif.getName().toLowerCase();
            if (nif.isLoopBack()) continue;
            if (name.startsWith("wl") || name.startsWith("wlan")) continue;  // WiFi
            if (name.startsWith("virbr") || name.startsWith("docker") || name.startsWith("veth")) continue;  // Virtual

            // Only include interfaces starting with "en" (Ethernet) or "eth"
            if (name.startsWith("en") || name.startsWith("eth")) {
                interfaceSelector.addItem(new InterfaceItem(nif));
            }
        }

        // Auto-select first interface if available
        if (interfaceSelector.getItemCount() > 0) {
            interfaceSelector.setSelectedIndex(0);
        }
    }

    private void startMonitoring() {
        InterfaceItem selected = (InterfaceItem) interfaceSelector.getSelectedItem();
        if (selected == null) {
            JOptionPane.showMessageDialog(this, "Please select a network interface",
                    "Error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        try {
            // Set up packet capture
            packetCapture.setNetworkInterface(selected.nif);
            packetCapture.setPacketHandler(packetHandler);

            // Set up traffic listener for GUI updates
            packetHandler.setTrafficListener(this::addTrafficEntry);

            // Start packet capture
            packetCapture.start();

            // Start DHCP server if enabled (disabled by default - use external dnsmasq)
            if (Boolean.parseBoolean(config.getProperty("dhcp.enabled", "false"))) {
                startDhcpServer();
            } else {
                dhcpStatusLabel.setText("DHCP: External (dnsmasq)");
                dhcpStatusLabel.setForeground(Color.BLUE);
            }

            // Update UI state
            startButton.setEnabled(false);
            stopButton.setEnabled(true);
            interfaceSelector.setEnabled(false);
            statusLabel.setText("Status: Monitoring on " + selected.nif.getName());
            statusLabel.setForeground(new Color(76, 175, 80));

            logger.info("Monitoring started on {}", selected.nif.getName());

        } catch (Exception e) {
            logger.error("Failed to start monitoring", e);
            JOptionPane.showMessageDialog(this,
                    "Failed to start monitoring: " + e.getMessage() +
                    "\n\nMake sure you have the required privileges (run as root/Administrator)" +
                    "\nand that libpcap/Npcap is installed.",
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void startDhcpServer() {
        try {
            dhcpServer = new DhcpServer(
                config.getProperty("dhcp.gateway", "10.0.0.1"),
                config.getProperty("dhcp.gateway", "10.0.0.1"),
                config.getProperty("dhcp.netmask", "255.255.255.0"),
                config.getProperty("dhcp.dns", "8.8.8.8"),
                config.getProperty("dhcp.range.start", "10.0.0.10"),
                config.getProperty("dhcp.range.end", "10.0.0.200"),
                Integer.parseInt(config.getProperty("dhcp.lease.hours", "24"))
            );

            dhcpServer.setLeaseListener(this::onNewLease);
            dhcpServer.start();

            dhcpStatusLabel.setText("DHCP: Running");
            dhcpStatusLabel.setForeground(new Color(76, 175, 80));

            logger.info("DHCP server started");

        } catch (Exception e) {
            logger.error("Failed to start DHCP server", e);
            dhcpStatusLabel.setText("DHCP: Failed - " + e.getMessage());
            dhcpStatusLabel.setForeground(Color.RED);
        }
    }

    private void stopMonitoring() {
        // Stop packet capture
        if (packetCapture.isRunning()) {
            packetCapture.stop();
        }

        // Stop DHCP server
        if (dhcpServer != null && dhcpServer.isRunning()) {
            dhcpServer.stop();
            dhcpStatusLabel.setText("DHCP: Stopped");
            dhcpStatusLabel.setForeground(Color.GRAY);
        }

        // Update UI state
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        interfaceSelector.setEnabled(true);
        statusLabel.setText("Status: Stopped");
        statusLabel.setForeground(Color.BLACK);

        logger.info("Monitoring stopped");
    }

    private void shutdown() {
        logger.info("Shutting down...");

        if (statsUpdateTimer != null) {
            statsUpdateTimer.stop();
        }

        stopMonitoring();
        trafficLogger.stop();
    }

    private void addTrafficEntry(String info) {
        // Parse the info string to extract components
        SwingUtilities.invokeLater(() -> {
            String[] parts = parseTrafficInfo(info);

            // Add to table
            trafficTableModel.addRow(parts);

            // Keep only max entries
            while (trafficTableModel.getRowCount() > maxDisplayEntries) {
                trafficTableModel.removeRow(0);
            }

            // Auto-scroll to bottom
            int lastRow = trafficTable.getRowCount() - 1;
            if (lastRow >= 0) {
                trafficTable.scrollRectToVisible(trafficTable.getCellRect(lastRow, 0, true));
            }
        });
    }

    private String[] parseTrafficInfo(String info) {
        String time = java.time.LocalTime.now().format(TIME_FORMAT);
        String protocol = "";
        String source = "";
        String destination = "";
        String details = "";

        // Parse protocol
        if (info.startsWith("TCP ")) {
            protocol = "TCP";
        } else if (info.startsWith("UDP ")) {
            protocol = "UDP";
        } else if (info.startsWith("DNS ")) {
            protocol = "DNS";
        } else if (info.startsWith("HTTP ")) {
            protocol = "HTTP";
        } else if (info.startsWith("HTTPS ")) {
            protocol = "HTTPS";
        }

        // Extract source and destination
        String[] parts = info.split("\\|");
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i].trim();
            if (part.contains("->")) {
                String[] endpoints = part.split("->");
                if (endpoints.length == 2) {
                    source = endpoints[0].trim();
                    destination = endpoints[1].trim();
                }
            } else if (i > 1) {
                if (!details.isEmpty()) details += " | ";
                details += part;
            }
        }

        return new String[]{time, protocol, source, destination, details};
    }

    private void onNewLease(DhcpLease lease) {
        SwingUtilities.invokeLater(() -> updateClientsTable());
    }

    private void updateClientsTable() {
        clientsTableModel.setRowCount(0);

        if (dhcpServer != null && dhcpServer.isRunning()) {
            // Internal DHCP server
            Collection<DhcpLease> leases = dhcpServer.getActiveLeases();
            for (DhcpLease lease : leases) {
                String remaining = formatDuration(lease.getRemainingSeconds());
                clientsTableModel.addRow(new Object[]{
                    lease.getMacAddress(),
                    lease.getIpAddress().getHostAddress(),
                    lease.getHostname() != null ? lease.getHostname() : "-",
                    remaining
                });
            }
        } else {
            // Read from dnsmasq leases file
            readDnsmasqLeases();
        }
    }

    private void readDnsmasqLeases() {
        // dnsmasq lease file locations
        String[] leaseFiles = {
            "/var/lib/dnsmasq/dnsmasq.leases",
            "/var/lib/misc/dnsmasq.leases",
            "/var/lib/dnsmasq/leases"
        };

        for (String path : leaseFiles) {
            java.io.File file = new java.io.File(path);
            if (file.exists() && file.canRead()) {
                try (java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.FileReader(file))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        // Format: timestamp mac ip hostname client-id
                        String[] parts = line.split("\\s+");
                        if (parts.length >= 4) {
                            long expiry = Long.parseLong(parts[0]);
                            String mac = parts[1].toUpperCase();
                            String ip = parts[2];
                            String hostname = parts[3].equals("*") ? "-" : parts[3];
                            long remaining = expiry - (System.currentTimeMillis() / 1000);
                            clientsTableModel.addRow(new Object[]{
                                mac, ip, hostname, formatDuration(remaining)
                            });
                        }
                    }
                } catch (Exception e) {
                    logger.debug("Could not read dnsmasq leases: {}", e.getMessage());
                }
                break;
            }
        }
    }

    private String formatDuration(long seconds) {
        if (seconds <= 0) return "Expired";
        long hours = seconds / 3600;
        long minutes = (seconds % 3600) / 60;
        return String.format("%dh %dm", hours, minutes);
    }

    private void startStatsTimer() {
        statsUpdateTimer = new Timer(1000, e -> updateStats());
        statsUpdateTimer.start();
    }

    private void updateStats() {
        packetCountLabel.setText("Packets: " + packetHandler.getPacketCount());
        tcpCountLabel.setText("TCP: " + packetHandler.getTcpCount());
        udpCountLabel.setText("UDP: " + packetHandler.getUdpCount());
        dnsCountLabel.setText("DNS: " + packetHandler.getDnsCount());
        httpCountLabel.setText("HTTP: " + packetHandler.getHttpCount());

        if (trafficLogger.getCurrentLogFile() != null) {
            logFileLabel.setText("Log: " + trafficLogger.getCurrentLogFile().getFileName());
        }

        // Update clients table periodically
        if (dhcpServer != null && dhcpServer.isRunning()) {
            updateClientsTable();
        }
    }

    /**
     * Wrapper class for network interface in combo box.
     */
    private static class InterfaceItem {
        final PcapNetworkInterface nif;

        InterfaceItem(PcapNetworkInterface nif) {
            this.nif = nif;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(nif.getName());

            // Get IP address from Java's NetworkInterface (more reliable)
            try {
                NetworkInterface javaIf = NetworkInterface.getByName(nif.getName());
                if (javaIf != null) {
                    Enumeration<InetAddress> addrs = javaIf.getInetAddresses();
                    StringBuilder ipStr = new StringBuilder();
                    while (addrs.hasMoreElements()) {
                        InetAddress addr = addrs.nextElement();
                        // Only show IPv4 addresses
                        if (addr instanceof java.net.Inet4Address) {
                            if (ipStr.length() > 0) ipStr.append(", ");
                            ipStr.append(addr.getHostAddress());
                        }
                    }
                    if (ipStr.length() > 0) {
                        sb.append(" [").append(ipStr).append("]");
                    } else {
                        sb.append(" [No IP]");
                    }
                }
            } catch (Exception e) {
                // Fall back to pcap4j info
                sb.append(" - ").append(PacketCapture.getInterfaceInfo(nif));
            }

            if (nif.getDescription() != null && !nif.getDescription().isEmpty()) {
                sb.append(" - ").append(nif.getDescription());
            }

            return sb.toString();
        }
    }
}
