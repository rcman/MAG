package com.psnserver.auth;

import com.psnserver.model.MockUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;

public class MockAuthService {
    private static final Logger logger = LoggerFactory.getLogger(MockAuthService.class);

    private final Map<String, MockUser> userDatabase = new HashMap<>();
    private final Map<String, String> activeSessions = new HashMap<>(); // token -> username
    private final RsaHandler rsaHandler;

    public MockAuthService() throws Exception {
        this.rsaHandler = new RsaHandler();
        this.rsaHandler.generateKeys();
        seedTestUsers();
    }

    private void seedTestUsers() {
        // Create default test user
        MockUser testUser = new MockUser();
        testUser.setUsername("test_user");
        testUser.setOnlineId("TestPlayer");
        testUser.setEmail("test@example.com");
        testUser.setHashedPassword(hashPassword("TestPass123!"));
        testUser.setAccountId("0000000000000001");
        testUser.setRegion("us");
        userDatabase.put("test_user", testUser);

        logger.info("Seeded test user: test_user / TestPass123!");
    }

    public void addUser(String username, String password, String onlineId) {
        MockUser user = new MockUser(username, hashPassword(password), onlineId);
        user.setEmail(username + "@example.com");
        userDatabase.put(username, user);
        logger.info("Added user: {} (Online ID: {})", username, onlineId);
    }

    public LoginResponse login(String username, String password) {
        LoginResponse response = new LoginResponse();

        MockUser user = userDatabase.get(username);
        if (user == null) {
            logger.warn("Login failed: user '{}' not found", username);
            response.setSuccess(false);
            response.setErrorCode("USER_NOT_FOUND");
            response.setErrorMessage("User not found");
            return response;
        }

        if (!verifyPassword(password, user.getHashedPassword())) {
            logger.warn("Login failed: invalid password for user '{}'", username);
            response.setSuccess(false);
            response.setErrorCode("INVALID_CREDENTIALS");
            response.setErrorMessage("Invalid credentials");
            return response;
        }

        // Generate session token
        String sessionToken = generateSessionToken();
        user.setSessionToken(sessionToken);
        user.setTokenExpiry(System.currentTimeMillis() + 3600000); // 1 hour

        activeSessions.put(sessionToken, username);

        response.setSuccess(true);
        response.setSessionToken(sessionToken);
        response.setAccountId(user.getAccountId());
        response.setOnlineId(user.getOnlineId());
        response.setRegion(user.getRegion());

        logger.info("Login successful for user '{}' (Online ID: {})", username, user.getOnlineId());
        return response;
    }

    public boolean validateSession(String sessionToken) {
        if (sessionToken == null || !activeSessions.containsKey(sessionToken)) {
            return false;
        }

        String username = activeSessions.get(sessionToken);
        MockUser user = userDatabase.get(username);

        return user != null && user.getTokenExpiry() > System.currentTimeMillis();
    }

    public MockUser getUserBySession(String sessionToken) {
        String username = activeSessions.get(sessionToken);
        return username != null ? userDatabase.get(username) : null;
    }

    public String refreshSession(String oldToken) {
        if (!validateSession(oldToken)) {
            return null;
        }

        String username = activeSessions.get(oldToken);
        String newToken = generateSessionToken();

        activeSessions.remove(oldToken);
        activeSessions.put(newToken, username);

        MockUser user = userDatabase.get(username);
        user.setSessionToken(newToken);
        user.setTokenExpiry(System.currentTimeMillis() + 3600000);

        logger.info("Session refreshed for user '{}'", username);
        return newToken;
    }

    public void logout(String sessionToken) {
        String username = activeSessions.remove(sessionToken);
        if (username != null) {
            MockUser user = userDatabase.get(username);
            if (user != null) {
                user.setSessionToken(null);
                user.setTokenExpiry(0);
            }
            logger.info("User '{}' logged out", username);
        }
    }

    public RsaHandler getRsaHandler() {
        return rsaHandler;
    }

    private String generateSessionToken() {
        return "PSN_" + UUID.randomUUID().toString().replace("-", "").toUpperCase();
    }

    private String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash password", e);
        }
    }

    private boolean verifyPassword(String input, String storedHash) {
        return hashPassword(input).equals(storedHash);
    }

    // Response class
    public static class LoginResponse {
        private boolean success;
        private String sessionToken;
        private String accountId;
        private String onlineId;
        private String region;
        private String errorCode;
        private String errorMessage;

        public boolean isSuccess() { return success; }
        public void setSuccess(boolean success) { this.success = success; }

        public String getSessionToken() { return sessionToken; }
        public void setSessionToken(String sessionToken) { this.sessionToken = sessionToken; }

        public String getAccountId() { return accountId; }
        public void setAccountId(String accountId) { this.accountId = accountId; }

        public String getOnlineId() { return onlineId; }
        public void setOnlineId(String onlineId) { this.onlineId = onlineId; }

        public String getRegion() { return region; }
        public void setRegion(String region) { this.region = region; }

        public String getErrorCode() { return errorCode; }
        public void setErrorCode(String errorCode) { this.errorCode = errorCode; }

        public String getErrorMessage() { return errorMessage; }
        public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
    }
}
