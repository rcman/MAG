package com.psnserver.model;

public class MockUser {
    private String username;
    private String hashedPassword;
    private String email;
    private String onlineId; // PSN Online ID
    private String accountId;
    private String sessionToken;
    private long tokenExpiry;
    private String region;

    public MockUser() {}

    public MockUser(String username, String hashedPassword, String onlineId) {
        this.username = username;
        this.hashedPassword = hashedPassword;
        this.onlineId = onlineId;
        this.accountId = "PSN_" + System.currentTimeMillis();
        this.region = "us";
    }

    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public String getHashedPassword() { return hashedPassword; }
    public void setHashedPassword(String hashedPassword) { this.hashedPassword = hashedPassword; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getOnlineId() { return onlineId; }
    public void setOnlineId(String onlineId) { this.onlineId = onlineId; }

    public String getAccountId() { return accountId; }
    public void setAccountId(String accountId) { this.accountId = accountId; }

    public String getSessionToken() { return sessionToken; }
    public void setSessionToken(String sessionToken) { this.sessionToken = sessionToken; }

    public long getTokenExpiry() { return tokenExpiry; }
    public void setTokenExpiry(long tokenExpiry) { this.tokenExpiry = tokenExpiry; }

    public String getRegion() { return region; }
    public void setRegion(String region) { this.region = region; }
}
