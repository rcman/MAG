package com.networkmonitor.logging;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * File-based traffic logger with date-based rotation.
 */
public class TrafficLogger {
    private static final Logger logger = LoggerFactory.getLogger(TrafficLogger.class);

    private static final DateTimeFormatter DATE_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd");
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");

    private final Path logDirectory;
    private final BlockingQueue<String> logQueue;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread writerThread;

    private BufferedWriter currentWriter;
    private LocalDate currentDate;
    private Path currentLogFile;

    private long totalLinesLogged = 0;

    public TrafficLogger(String logDirectoryPath) throws IOException {
        this.logDirectory = Paths.get(logDirectoryPath);
        this.logQueue = new LinkedBlockingQueue<>(10000);

        // Create log directory if it doesn't exist
        if (!Files.exists(logDirectory)) {
            Files.createDirectories(logDirectory);
            logger.info("Created log directory: {}", logDirectory);
        }
    }

    public void start() {
        if (running.get()) {
            return;
        }

        running.set(true);
        writerThread = new Thread(this::writerLoop, "Traffic-Logger");
        writerThread.setDaemon(true);
        writerThread.start();

        logger.info("Traffic logger started, writing to: {}", logDirectory);
    }

    public void stop() {
        running.set(false);

        if (writerThread != null) {
            writerThread.interrupt();
            try {
                writerThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        closeWriter();
        logger.info("Traffic logger stopped. Total lines logged: {}", totalLinesLogged);
    }

    public void log(String message) {
        if (!running.get()) {
            return;
        }

        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        String logLine = String.format("[%s] %s", timestamp, message);

        if (!logQueue.offer(logLine)) {
            logger.warn("Log queue full, dropping message");
        }
    }

    private void writerLoop() {
        while (running.get() || !logQueue.isEmpty()) {
            try {
                String line = logQueue.poll(100, java.util.concurrent.TimeUnit.MILLISECONDS);
                if (line != null) {
                    writeLine(line);
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (IOException e) {
                logger.error("Error writing log line", e);
            }
        }

        // Drain remaining queue
        String line;
        while ((line = logQueue.poll()) != null) {
            try {
                writeLine(line);
            } catch (IOException e) {
                logger.error("Error writing log line during shutdown", e);
            }
        }
    }

    private void writeLine(String line) throws IOException {
        LocalDate today = LocalDate.now();

        // Check if we need to rotate to a new file
        if (currentWriter == null || !today.equals(currentDate)) {
            rotateFile(today);
        }

        currentWriter.write(line);
        currentWriter.newLine();
        currentWriter.flush();
        totalLinesLogged++;
    }

    private void rotateFile(LocalDate date) throws IOException {
        closeWriter();

        currentDate = date;
        String fileName = String.format("network-traffic-%s.log", date.format(DATE_FORMAT));
        currentLogFile = logDirectory.resolve(fileName);

        currentWriter = new BufferedWriter(
            new OutputStreamWriter(
                new FileOutputStream(currentLogFile.toFile(), true),
                StandardCharsets.UTF_8
            )
        );

        logger.info("Logging to: {}", currentLogFile);
    }

    private void closeWriter() {
        if (currentWriter != null) {
            try {
                currentWriter.flush();
                currentWriter.close();
            } catch (IOException e) {
                logger.error("Error closing log file", e);
            }
            currentWriter = null;
        }
    }

    public Path getCurrentLogFile() {
        return currentLogFile;
    }

    public Path getLogDirectory() {
        return logDirectory;
    }

    public long getTotalLinesLogged() {
        return totalLinesLogged;
    }

    public boolean isRunning() {
        return running.get();
    }
}
