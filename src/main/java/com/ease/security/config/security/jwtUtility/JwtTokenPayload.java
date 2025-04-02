package com.ease.security.config.security.jwtUtility;

import java.io.Serial;
import java.util.List;
import java.util.UUID;

import lombok.Data;

@Data
public class JwtTokenPayload {

    @Serial
    private static final long serialVersionUID = 1L;
    private UUID userId;
    private String email;
    private String tenantId;
    private List<String> roles;

    public JwtTokenPayload(UUID userId, String email, String tenantId, List<String> roles) {
        this.email = email;
        this.userId = userId;
        this.roles = roles;
        this.tenantId = tenantId;
    }

}
