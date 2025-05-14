package com.ease.security.service;

import java.util.List;
import java.util.UUID;

import com.ease.security.model.UserAuthDetails;
import com.fasterxml.jackson.core.JsonProcessingException;

public interface UserAuthDetailService {

    public UserAuthDetails saveDirectlyActivatedUserDetails(UserAuthDetails userAuthDetails) throws Exception;
    public UserAuthDetails getUserById(UUID id);
    public UserAuthDetails getUserByEmail(String email);
    public List<UserAuthDetails> getAllUsers();
    public void deleteUserById(UUID id);

    public String initilizeSchemaafterSuccessfullSchemaCreation(String schemaName) throws JsonProcessingException;
}
