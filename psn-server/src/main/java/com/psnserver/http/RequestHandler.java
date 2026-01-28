package com.psnserver.http;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.psnserver.auth.MockAuthService;
import com.psnserver.http.HttpServer.HttpRequest;
import com.psnserver.http.HttpServer.HttpResponse;
import com.psnserver.model.MockUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.Map;

public class RequestHandler {
    private static final Logger logger = LoggerFactory.getLogger(RequestHandler.class);

    private final MockAuthService authService;
    private final Gson gson = new GsonBuilder().setPrettyPrinting().create();

    public RequestHandler(MockAuthService authService) {
        this.authService = authService;
    }

    public HttpResponse handle(HttpRequest request) {
        String path = request.getPath();
        String method = request.getMethod();

        logger.debug("Handling {} {}", method, path);

        // Route requests
        try {
            // PlayStation Update endpoints
            if (path.contains("/update/") || path.contains("/ps3/update")) {
                return handleUpdateCheck(request);
            }

            // Authentication endpoints
            if (path.contains("/auth") || path.contains("/login") || path.contains("/signin")) {
                return handleAuth(request);
            }

            // Session/Token endpoints
            if (path.contains("/session") || path.contains("/token")) {
                return handleSession(request);
            }

            // STUN-related endpoints
            if (path.contains("/stun") || path.contains("/nat")) {
                return handleStun(request);
            }

            // Download endpoints
            if (path.contains("/download") || path.contains("/dl/")) {
                return handleDownload(request);
            }

            // Profile/User endpoints
            if (path.contains("/profile") || path.contains("/user")) {
                return handleProfile(request);
            }

            // Root/Health check
            if (path.equals("/") || path.equals("/health")) {
                return handleHealthCheck(request);
            }

            // Default: Log and return mock response
            logger.info("Unhandled path: {} {}", method, path);
            return handleDefault(request);

        } catch (Exception e) {
            logger.error("Error handling request: {}", e.getMessage(), e);
            return errorResponse(500, "Internal Server Error", e.getMessage());
        }
    }

    private HttpResponse handleUpdateCheck(HttpRequest request) {
        logger.info("Update check request: {}", request.getPath());

        // Return "no update available" response
        HttpResponse response = new HttpResponse(200, "OK");
        response.addHeader("Content-Type", "text/xml");

        String xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <update>
                <status>no_update</status>
                <version>current</version>
            </update>
            """;

        response.setBody(xml);
        return response;
    }

    private HttpResponse handleAuth(HttpRequest request) {
        logger.info("Auth request: {} {}", request.getMethod(), request.getPath());

        if (request.getMethod().equals("POST")) {
            // Parse login credentials from body
            String body = request.getBody();
            String username = extractParam(body, "username");
            String password = extractParam(body, "password");

            if (username == null) username = extractParam(body, "user");
            if (password == null) password = extractParam(body, "pass");

            // If no credentials in body, check headers
            if (username == null) {
                username = "test_user";
                password = "TestPass123!";
            }

            MockAuthService.LoginResponse loginResponse = authService.login(username, password);

            HttpResponse response = new HttpResponse(200, "OK");
            response.addHeader("Content-Type", "application/json");

            Map<String, Object> result = new HashMap<>();
            if (loginResponse.isSuccess()) {
                result.put("status", "success");
                result.put("session_token", loginResponse.getSessionToken());
                result.put("account_id", loginResponse.getAccountId());
                result.put("online_id", loginResponse.getOnlineId());
                result.put("region", loginResponse.getRegion());
                result.put("ticket", generateTicket(loginResponse.getAccountId()));
            } else {
                result.put("status", "error");
                result.put("error_code", loginResponse.getErrorCode());
                result.put("error_message", loginResponse.getErrorMessage());
            }

            response.setBody(gson.toJson(result));
            return response;
        }

        // GET request - return auth form or status
        HttpResponse response = new HttpResponse(200, "OK");
        response.addHeader("Content-Type", "application/json");
        response.setBody("{\"status\": \"ready\", \"server\": \"mock-psn\"}");
        return response;
    }

    private HttpResponse handleSession(HttpRequest request) {
        logger.info("Session request: {}", request.getPath());

        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        HttpResponse response = new HttpResponse(200, "OK");
        response.addHeader("Content-Type", "application/json");

        Map<String, Object> result = new HashMap<>();
        if (token != null && authService.validateSession(token)) {
            MockUser user = authService.getUserBySession(token);
            result.put("status", "valid");
            result.put("online_id", user.getOnlineId());
            result.put("account_id", user.getAccountId());
        } else {
            result.put("status", "invalid");
            result.put("message", "Session expired or invalid");
        }

        response.setBody(gson.toJson(result));
        return response;
    }

    private HttpResponse handleStun(HttpRequest request) {
        logger.info("STUN request: {}", request.getPath());

        // Return mock STUN response
        HttpResponse response = new HttpResponse(200, "OK");
        response.addHeader("Content-Type", "application/json");

        Map<String, Object> result = new HashMap<>();
        result.put("status", "success");
        result.put("nat_type", 2); // Type 2 = Moderate NAT
        result.put("external_ip", "10.0.0.1");
        result.put("external_port", 3478);

        response.setBody(gson.toJson(result));
        return response;
    }

    private HttpResponse handleDownload(HttpRequest request) {
        logger.info("Download request: {}", request.getPath());

        // Return mock download response
        HttpResponse response = new HttpResponse(200, "OK");
        response.addHeader("Content-Type", "application/json");

        Map<String, Object> result = new HashMap<>();
        result.put("status", "available");
        result.put("url", "http://10.0.0.1/mock-download");
        result.put("size", 0);

        response.setBody(gson.toJson(result));
        return response;
    }

    private HttpResponse handleProfile(HttpRequest request) {
        logger.info("Profile request: {}", request.getPath());

        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        }

        HttpResponse response = new HttpResponse(200, "OK");
        response.addHeader("Content-Type", "application/json");

        Map<String, Object> result = new HashMap<>();
        if (token != null && authService.validateSession(token)) {
            MockUser user = authService.getUserBySession(token);
            result.put("online_id", user.getOnlineId());
            result.put("account_id", user.getAccountId());
            result.put("region", user.getRegion());
            result.put("avatar_url", "http://10.0.0.1/avatar/default.png");
        } else {
            result.put("error", "Not authenticated");
        }

        response.setBody(gson.toJson(result));
        return response;
    }

    private HttpResponse handleHealthCheck(HttpRequest request) {
        HttpResponse response = new HttpResponse(200, "OK");
        response.addHeader("Content-Type", "application/json");

        Map<String, Object> result = new HashMap<>();
        result.put("status", "online");
        result.put("server", "PSN Mock Server");
        result.put("version", "1.0");

        response.setBody(gson.toJson(result));
        return response;
    }

    private HttpResponse handleDefault(HttpRequest request) {
        // Log the full request for debugging
        logger.info("Default handler - Method: {}, Path: {}", request.getMethod(), request.getPath());
        logger.info("Headers: {}", request.getHeaders());
        if (!request.getBody().isEmpty()) {
            logger.info("Body: {}", request.getBody());
        }

        // Return generic success response
        HttpResponse response = new HttpResponse(200, "OK");
        response.addHeader("Content-Type", "application/json");

        Map<String, Object> result = new HashMap<>();
        result.put("status", "ok");
        result.put("path", request.getPath());
        result.put("message", "Mock PSN Server - endpoint logged");

        response.setBody(gson.toJson(result));
        return response;
    }

    private HttpResponse errorResponse(int code, String message, String details) {
        HttpResponse response = new HttpResponse(code, message);
        response.addHeader("Content-Type", "application/json");

        Map<String, Object> result = new HashMap<>();
        result.put("error", message);
        result.put("details", details);

        response.setBody(gson.toJson(result));
        return response;
    }

    private String extractParam(String body, String param) {
        if (body == null || body.isEmpty()) return null;

        // Try JSON format
        if (body.trim().startsWith("{")) {
            try {
                @SuppressWarnings("unchecked")
                Map<String, Object> json = gson.fromJson(body, Map.class);
                Object value = json.get(param);
                return value != null ? value.toString() : null;
            } catch (Exception e) {
                // Not valid JSON, try form format
            }
        }

        // Try form-urlencoded format
        for (String part : body.split("&")) {
            String[] kv = part.split("=", 2);
            if (kv.length == 2 && kv[0].equals(param)) {
                return kv[1];
            }
        }

        return null;
    }

    private String generateTicket(String accountId) {
        // Generate a mock ticket (base64 encoded)
        String ticketData = accountId + ":" + System.currentTimeMillis() + ":mock_signature";
        return java.util.Base64.getEncoder().encodeToString(ticketData.getBytes());
    }
}
