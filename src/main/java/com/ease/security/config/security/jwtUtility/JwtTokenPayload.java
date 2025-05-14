package com.ease.security.config.security.jwtUtility;

import java.io.Serial;
import java.util.List;
import java.util.UUID;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class JwtTokenPayload {

    @Serial
    private static final long serialVersionUID = 1L;
    @JsonProperty(value = "userId")
    private UUID userId;
    @JsonProperty(value = "email")
    private String email;
    @JsonProperty(value = "tenantId")
    private String tenantId;
    @JsonProperty(value = "roles")
    private List<String> roles;

}
