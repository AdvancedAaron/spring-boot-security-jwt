package com.aaron.springjwt.repository;

import com.aaron.springjwt.models.ERole;
import com.aaron.springjwt.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(ERole role);
}
