package com.ease.security.service;

import java.util.List;
import java.util.UUID;

import com.ease.security.config.security.jwtUtility.JJWTTokenProvider;
import com.ease.security.config.security.jwtUtility.JwtTokenPayload;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.ease.security.model.UserAuthDetails;
import com.ease.security.repository.UserAuthDetailsDao;
import com.ease.security.utility.PasswordBycryptEncrypt;
import org.springframework.web.client.RestTemplate;

@Service
@Slf4j
public class UserAuthDetailServiceImpl implements UserAuthDetailService {

    @Autowired
    private UserAuthDetailsDao userAuthDetailsDao;

    @Autowired
    private PasswordBycryptEncrypt passwordBycryptEncrypt;

    @Autowired
    private JJWTTokenProvider jjwtTokenProvider;

    @Override
    public UserAuthDetails saveDirectlyActivatedUserDetails(UserAuthDetails userAuthDetails) throws Exception{
        userAuthDetails.setPassword(passwordBycryptEncrypt.encryptPassword(userAuthDetails.getPassword()));
        try {
            userAuthDetails.setLast_active_date(System.currentTimeMillis());
            userAuthDetails.setJoined_at(System.currentTimeMillis());
            userAuthDetails.setPassword_last_active_date(System.currentTimeMillis());
            userAuthDetails.setFailed_login_atampts(0L);
            userAuthDetails = userAuthDetailsDao.save(userAuthDetails);
        } catch (Exception e) {
            throw new Exception("Error while saving user details: " + e.getMessage(), e);
        }

        return userAuthDetails;
    }

    @Override
    public UserAuthDetails getUserById(UUID id) {
        UserAuthDetails userAuthDetails = userAuthDetailsDao.findById(id).orElseThrow(() -> new RuntimeException("User not found with id: " + id));
        return userAuthDetails;}

    @Override
    public UserAuthDetails getUserByEmail(String email) {
        UserAuthDetails userAuthDetails = userAuthDetailsDao.findByEmail(email);
        return userAuthDetails;
    }

    @Override
    public List<UserAuthDetails> getAllUsers() {

        List<UserAuthDetails> userAuthDetails = userAuthDetailsDao.findAll();
        if (userAuthDetails.isEmpty()) {
            throw new RuntimeException("No users found in the system.");
        }
        return userAuthDetails;
    }

    @Override
    public void deleteUserById(UUID id) {
        // TODO Auto-generated method stub
        throw new UnsupportedOperationException("Unimplemented method 'deleteUserById'");
    }

    @Override
    public String initilizeSchemaafterSuccessfullSchemaCreation(String schemaName) throws JsonProcessingException {
        SecurityContext sch = SecurityContextHolder.getContext();
        JwtTokenPayload jwtTokenPayload = (JwtTokenPayload) sch.getAuthentication().getDetails();
        String prvtToken = jjwtTokenProvider.generatePrivateJwtToken(jwtTokenPayload);
        log.info("Private token generated successfully: {}", prvtToken);
        RestTemplate rt = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer "+prvtToken);
        HttpEntity<String> entity = new HttpEntity<>(schemaName, headers);

        ResponseEntity<String> response = rt.postForEntity("http://localhost:8080/test/api/initilize-schema",entity,String.class);
//        ResponseEntity responseEntity =  rt.exchange("http://localhost:8080/test/api/initilize-schema", HttpMethod.POST,entity, String.class);
        return (String) response.getBody();
    }


}
