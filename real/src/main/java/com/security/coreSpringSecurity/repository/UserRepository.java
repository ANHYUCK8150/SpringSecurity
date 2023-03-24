package com.security.coreSpringSecurity.repository;

import com.security.coreSpringSecurity.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {
}
