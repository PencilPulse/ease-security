package com.ease.security.config.security.authUserDetails;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.ease.security.model.UserAuthDetails;
import com.ease.security.repository.UserAuthDetailsDao;

import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j
public class UserDetailsServiceImpl implements UserDetailsService{
    
    @Autowired
    UserAuthDetailsDao userAuthDetailsDao;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserAuthDetails userAuthDetails = userAuthDetailsDao.findByEmail(username);
        if(userAuthDetails == null){
            throw new UsernameNotFoundException("provided user not present in system");
        }
        UserDetailsImpl userDetails = new UserDetailsImpl();
        userDetails.setPassword(userAuthDetails.getPassword());
        userDetails.setUsername(username);
        return userDetails;
    }

    

}
