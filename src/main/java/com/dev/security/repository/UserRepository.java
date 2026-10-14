package com.dev.security.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.dev.security.entity.User;

public interface UserRepository extends JpaRepository<User, Long>{
    Optional<User> findUserByEmail(String email);
}
