package com.example.demo.appuser;

import org.springframework.stereotype.Repository;

import java.util.Optional;
@Repository
public interface AppUserRepository {
    Optional<AppUser> findByEmail(String Email);
}
