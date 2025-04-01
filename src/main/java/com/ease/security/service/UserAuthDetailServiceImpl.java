package com.ease.security.service;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.ease.security.model.UserAuthDetails;
import com.ease.security.repository.UserAuthDetailsDao;
import com.ease.security.utility.PasswordBycryptEncrypt;

@Service
public class UserAuthDetailServiceImpl implements UserAuthDetailService {

    @Autowired
    private UserAuthDetailsDao userAuthDetailsDao;

    @Autowired
    private PasswordBycryptEncrypt passwordBycryptEncrypt;

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

}
