package com.ease.security.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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
    

    // @GetMapping("/getUserById/{id}")
    // public ResponseEntity<UserAuthDetails> getUserById(@PathVariable UUID id) {
    //     return new ResponseEntity<>(userAuthDetailsService.getUserById(id), HttpStatus.OK);
    // }
    // @PostMapping("/createUser")

}
