package com.security.coreSpringSecurity.service.impl;

import com.security.coreSpringSecurity.domain.Account;
import com.security.coreSpringSecurity.repository.UserRepository;
import com.security.coreSpringSecurity.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service("userService")
public class UserServiceImpl implements UserService {

    @Autowired
    private UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {

        userRepository.save(account);

    }
}
