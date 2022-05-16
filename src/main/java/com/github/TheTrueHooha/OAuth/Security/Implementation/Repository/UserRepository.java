package com.github.TheTrueHooha.OAuth.Security.Implementation.Repository;

import com.github.TheTrueHooha.OAuth.Security.Implementation.Model.Users;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Users, Long> {

    Users findByEmail (String email);
}
