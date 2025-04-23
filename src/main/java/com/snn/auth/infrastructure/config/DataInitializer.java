package com.snn.auth.infrastructure.config;

import com.snn.auth.application.RoleRepository;
import com.snn.auth.application.UserRepository;
import com.snn.auth.domain.Role;
import com.snn.auth.domain.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

  private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

  private final RoleRepository roleRepository;
  private final UserRepository userRepository;
  private final PasswordEncoder passwordEncoder;

  public DataInitializer(RoleRepository roleRepository, UserRepository userRepository,
      PasswordEncoder passwordEncoder) {
    this.roleRepository = roleRepository;
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
  }

  @Override
  public void run(String... args) throws Exception {
    log.info("Initializing data...");

    String roleAdminName = "ROLE_ADMIN";
    String roleUserName = "ROLE_USER";

    Role adminRole = getRole(roleAdminName);
    Role userRole = getRole(roleUserName);

    String adminUserName = "admin";
    if (!userRepository.existsUserByUsername(adminUserName)) {
      log.info("Creating {} user.", adminUserName);

      String encoded = passwordEncoder.encode("password123");
      User adminUser = new User(adminUserName, "admin@user.com", encoded);
      adminUser.addRole(adminRole);
      adminUser.addRole(userRole);
      userRepository.save(adminUser);

      log.info("{} user created.", adminUserName);
    }

    String regularUserName = "regular";
    if (!userRepository.existsUserByUsername(regularUserName)) {
      log.info("Creating {} user.", regularUserName);

      String encoded = passwordEncoder.encode("password123");
      User adminUser = new User(regularUserName, "regular@user.com", encoded);
      adminUser.addRole(userRole);
      userRepository.save(adminUser);

      log.info("{} user created.", regularUserName);
    }

    log.info("Data initialization finished.");
  }

  private Role getRole(String roleName) {
    return roleRepository.findByName(roleName).orElseGet(() -> {
      log.info("Creating {} role.", roleName);
      return roleRepository.save(new Role(roleName));
    });
  }
}
