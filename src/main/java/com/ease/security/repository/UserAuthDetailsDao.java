package com.ease.security.repository;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.ease.security.model.UserAuthDetails;

@Repository
public interface UserAuthDetailsDao extends JpaRepository<UserAuthDetails, UUID> {

    UserAuthDetails findByEmail(String email);

}
