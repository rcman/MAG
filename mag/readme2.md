I can provide more details about creating a mock authentication system for legitimate testing and learning purposes. This is useful for testing your own applications without connecting to real services.

Complete Mock Authentication System Example

Here's a more sophisticated mock login system:

```java
// User model for mock database
public class MockUser {
    private String username;
    private String encryptedPassword;
    private String email;
    private String userId;
    private String sessionToken;
    private long tokenExpiry;
    
    // Constructors, getters, setters
}

// Mock authentication service
public class MockAuthService {
    private Map<String, MockUser> mockDatabase = new HashMap<>();
    private Map<String, String> activeSessions = new HashMap<>();
    
    public MockAuthService() {
        // Initialize with test users
        seedTestUsers();
    }
    
    private void seedTestUsers() {
        MockUser testUser = new MockUser();
        testUser.setUsername("test_user");
        testUser.setUserId("PSN_TEST_001");
        testUser.setEmail("test@example.com");
        // Store hashed password, not plain text
        testUser.setEncryptedPassword(hashPassword("TestPass123!"));
        mockDatabase.put("test_user", testUser);
    }
    
    // Simulate login process
    public MockLoginResponse login(String username, String password) {
        MockLoginResponse response = new MockLoginResponse();
        
        if (!mockDatabase.containsKey(username)) {
            response.setSuccess(false);
            response.setErrorCode("USER_NOT_FOUND");
            return response;
        }
        
        MockUser user = mockDatabase.get(username);
        
        // Verify password (in real system, compare hashes)
        if (verifyPassword(password, user.getEncryptedPassword())) {
            // Generate mock session token
            String sessionToken = generateSessionToken();
            user.setSessionToken(sessionToken);
            user.setTokenExpiry(System.currentTimeMillis() + 3600000); // 1 hour
            
            activeSessions.put(sessionToken, username);
            
            response.setSuccess(true);
            response.setSessionToken(sessionToken);
            response.setUserId(user.getUserId());
            response.setUsername(user.getUsername());
        } else {
            response.setSuccess(false);
            response.setErrorCode("INVALID_CREDENTIALS");
        }
        
        return response;
    }
    
    // Simulate session validation
    public boolean validateSession(String sessionToken) {
        if (!activeSessions.containsKey(sessionToken)) {
            return false;
        }
        
        String username = activeSessions.get(sessionToken);
        MockUser user = mockDatabase.get(username);
        
        // Check token expiry
        return user != null && user.getTokenExpiry() > System.currentTimeMillis();
    }
    
    // Simulate token refresh
    public String refreshSession(String oldToken) {
        if (validateSession(oldToken)) {
            String newToken = generateSessionToken();
            String username = activeSessions.get(oldToken);
            
            activeSessions.remove(oldToken);
            activeSessions.put(newToken, username);
            
            MockUser user = mockDatabase.get(username);
            user.setSessionToken(newToken);
            user.setTokenExpiry(System.currentTimeMillis() + 3600000);
            
            return newToken;
        }
        return null;
    }
    
    // Helper methods
    private String generateSessionToken() {
        return "MOCK_TOKEN_" + UUID.randomUUID().toString().replace("-", "");
    }
    
    private String hashPassword(String password) {
        // In a real mock, you'd use a proper hashing algorithm
        return "hashed_" + password; // Simplified for example
    }
    
    private boolean verifyPassword(String input, String storedHash) {
        return hashPassword(input).equals(storedHash);
    }
}

// Response object
public class MockLoginResponse {
    private boolean success;
    private String sessionToken;
    private String userId;
    private String username;
    private String errorCode;
    
    // Getters and setters
}
```

Testing Scenarios You Can Simulate

```java
// Test cases for your mock
public class AuthTestScenarios {
    
    public void testSuccessfulLogin() {
        MockAuthService auth = new MockAuthService();
        MockLoginResponse response = auth.login("test_user", "TestPass123!");
        
        assert response.isSuccess();
        assert response.getSessionToken() != null;
        assert auth.validateSession(response.getSessionToken());
    }
    
    public void testFailedLogin() {
        MockAuthService auth = new MockAuthService();
        MockLoginResponse response = auth.login("wrong_user", "wrongpass");
        
        assert !response.isSuccess();
        assert response.getErrorCode().equals("USER_NOT_FOUND");
    }
    
    public void testSessionExpiry() throws InterruptedException {
        MockAuthService auth = new MockAuthService();
        MockLoginResponse response = auth.login("test_user", "TestPass123!");
        
        // Simulate expiry by manipulating the mock
        // (In real test, you'd mock time or set short expiry)
        assert auth.validateSession(response.getSessionToken());
        
        // Test token refresh
        String newToken = auth.refreshSession(response.getSessionToken());
        assert newToken != null;
        assert auth.validateSession(newToken);
    }
}
```

Advanced Features to Implement

1. Rate Limiting Simulation:

```java
public class MockRateLimiter {
    private Map<String, Integer> attemptCount = new HashMap<>();
    
    public boolean allowAttempt(String ip) {
        int attempts = attemptCount.getOrDefault(ip, 0);
        if (attempts >= 5) {
            return false; // Block after 5 attempts
        }
        attemptCount.put(ip, attempts + 1);
        return true;
    }
}
```

1. Two-Factor Authentication Mock:

```java
public class Mock2FAService {
    public String generate2FACode(String userId) {
        return String.format("%06d", new Random().nextInt(999999));
    }
    
    public boolean verify2FACode(String userId, String code) {
        // Mock verification logic
        return code != null && code.length() == 6;
    }
}
```

1. Error Scenario Simulation:

```java
public enum MockErrorScenario {
    NETWORK_TIMEOUT,
    SERVICE_UNAVAILABLE,
    MAINTENANCE_MODE,
    INVALID_RESPONSE
}

public MockLoginResponse simulateError(MockErrorScenario scenario) {
    // Return appropriate error responses for testing
}
```

Best Practices for Mock Authentication

1. Never store real credentials in mock systems
2. Use environment variables for configuration
3. Implement proper logging for debugging
4. Add validation for all inputs
5. Include security headers in mock responses
6. Simulate realistic delays (50-200ms) for network latency

Legal Learning Paths

If you want to learn about authentication professionally:

1. Study OAuth 2.0 and OpenID Connect
2. Learn about JSON Web Tokens (JWT)
3. Practice with Spring Security or Apache Shiro
4. Take courses on application security
5. Participate in CTF (Capture The Flag) competitions (legal ones)

Remember: Always use mock systems only for testing your own applications, never for attempting to access or impersonate real services without 