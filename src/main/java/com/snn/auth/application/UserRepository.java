package com.snn.auth.application;

import com.snn.auth.domain.User;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {

  Optional<User> findByUsername(String username);

  Boolean existsUserByUsername(String username);

  Boolean existsUserByEmail(String email);
}
