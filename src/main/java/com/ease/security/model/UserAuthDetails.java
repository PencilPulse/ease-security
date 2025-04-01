package com.ease.security.model;

import java.util.UUID;

import com.ease.security.Enum.UserStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.Email;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "USER_AUTH_DETAILS")
public class UserAuthDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "id", updatable = false, nullable = false)
    UUID id;

    @Column(name = "email", unique = true, nullable = false)
    @Email
    String email;

    @Column(name = "last_active_date")
    Long last_active_date;

    @Column(name = "joined_at")
    Long joined_at;

    @Column(name = "password", nullable = false)
    String password;

    @Column(name = "is_admin")
    Boolean is_admin;

    @Column(name = "failed_login_atampts")
    Long failed_login_atampts;

    @Column(name = "status")
    @Enumerated(EnumType.STRING)
    UserStatus status;

    @Column(name = "password_last_active_date")
    Long password_last_active_date;

}
