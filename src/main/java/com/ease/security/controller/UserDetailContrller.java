package com.ease.security.controller;

import java.util.List;

import com.ease.security.config.security.jwtUtility.JwtTokenPayload;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ease.security.model.UserAuthDetails;
import com.ease.security.service.UserAuthDetailService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;


@RestController
@RequestMapping("/api/v1/user")
public class UserDetailContrller {

    @Autowired
    UserAuthDetailService userAuthDetailsService;

    @GetMapping("/getAllUsers")
    public ResponseEntity<List<UserAuthDetails>> getAllUsers() {
        return new ResponseEntity<>(userAuthDetailsService.getAllUsers(), HttpStatus.OK);
    }

    @PostMapping("/onboard-users")
    public UserAuthDetails saveDirectlyActivatedUserDetails(@RequestBody UserAuthDetails userAuthDetails) throws Exception {
        UserAuthDetails newUser = userAuthDetailsService.saveDirectlyActivatedUserDetails(userAuthDetails);
        return newUser;
    }
    
    @GetMapping("/getUserByEmail/{email}")
    public ResponseEntity<UserAuthDetails> getUserByEmail(String email) {
        return new ResponseEntity<>(userAuthDetailsService.getUserByEmail(email), HttpStatus.OK);
    }

    @PostMapping("/initilze-schema")
    public ResponseEntity<String> createSchemaInProfile() throws JsonProcessingException {
        SecurityContext sch = SecurityContextHolder.getContext();
        JwtTokenPayload jwtTokenPayload = (JwtTokenPayload) sch.getAuthentication().getDetails();
        String msg = userAuthDetailsService.initilizeSchemaafterSuccessfullSchemaCreation(jwtTokenPayload.getTenantId());
        return new ResponseEntity<>(msg, HttpStatus.CREATED);
    }

    // @GetMapping("/getUserById/{id}")
    // public ResponseEntity<UserAuthDetails> getUserById(@PathVariable UUID id) {
    //     return new ResponseEntity<>(userAuthDetailsService.getUserById(id), HttpStatus.OK);
    // }
    // @PostMapping("/createUser")

}
