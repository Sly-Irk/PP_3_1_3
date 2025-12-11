package ru.javamentor.Spring_Security.services;

import org.springframework.security.core.Authentication;
import ru.javamentor.Spring_Security.models.Role;
import ru.javamentor.Spring_Security.models.User;

import java.util.List;
import java.util.Optional;

public interface UserService {

    List<User> getAllUsers();

    User getUserById(Long id);

    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);

    void createUser(String username, String password, String surname, Integer age, String email, List<Long> roleIds);

    String regUser(User user);

    void updateUser(User user, List<Long> roleIds);

    void contUpdateUser(Long id, String username, String password, String surname, Integer age, String email, List<Long> roleIds);

    void deleteUser(Long id);

    void addRoleToUser(Long userId, Role role);

    String authUser(Authentication authentication);
}