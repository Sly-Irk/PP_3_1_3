package ru.javamentor.Spring_Security.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import ru.javamentor.Spring_Security.exceptions.EmailException;
import ru.javamentor.Spring_Security.exceptions.PasswordException;
import ru.javamentor.Spring_Security.exceptions.UserNameExistException;
import ru.javamentor.Spring_Security.exceptions.UserRoleException;
import ru.javamentor.Spring_Security.models.Role;
import ru.javamentor.Spring_Security.models.User;
import ru.javamentor.Spring_Security.repositories.RoleRepository;
import ru.javamentor.Spring_Security.repositories.UserRepository;

import java.util.*;
import java.util.stream.Collectors;

@Service
@Transactional
public class UserServiceImpl implements UserService, UserDetailsService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserServiceImpl(UserRepository userRepository,
                           RoleRepository roleRepository,
                           PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    private Role getOrCreateRole(String name) {
        return roleRepository.findByName(name)
                .orElseGet(() -> roleRepository.save(new Role(name)));
    }

    private Set<Role> resolveRoles(Collection<Long> ids) {
        if (ids == null || ids.isEmpty()) {
            return Set.of(getOrCreateRole("ROLE_USER"));
        }
        List<Role> found = roleRepository.findAllByIdIn(ids);
        if (found.size() != ids.size()) {
            Set<Long> existing = found.stream().map(Role::getId).collect(Collectors.toSet());
            List<Long> missing = ids.stream().filter(id -> !existing.contains(id)).toList();
            throw new UserRoleException("Роли с ID " + missing + " не найдены");
        }
        return new HashSet<>(found);
    }

    private boolean isPasswordEncoded(String password) {
        return password != null && password.startsWith("$2a$");
    }

    private void validateNewUser(User user) {
        if (user.getPassword() == null || user.getPassword().length() < 4)
            throw new PasswordException("Пароль должен быть минимум 4 символа");
        userRepository.findByUsername(user.getUsername())
                .ifPresent(u -> {
                    throw new UserNameExistException("Этот логин уже занят");
                });
        if (user.getEmail() != null)
            userRepository.findByEmail(user.getEmail())
                    .ifPresent(u -> {
                        throw new EmailException("Этот E-mail уже занят");
                    });
    }

    private void validateUpdate(User existing, User updated) {
        if (!Objects.equals(existing.getUsername(), updated.getUsername())) {
            userRepository.findByUsername(updated.getUsername())
                    .filter(u -> !u.getId().equals(existing.getId()))
                    .ifPresent(u -> {
                        throw new UserNameExistException("Этот логин уже занят");
                    });
        }
        if (!Objects.equals(existing.getEmail(), updated.getEmail())) {
            userRepository.findByEmail(updated.getEmail())
                    .filter(u -> !u.getId().equals(existing.getId()))
                    .ifPresent(u -> {
                        throw new EmailException("Этот E-mail уже занят");
                    });
        }
    }

    @Override
    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @Override
    @Transactional(readOnly = true)
    public User getUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + id));
    }

    @Override
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public void createUser(String username, String password, String surname, Integer age, String email, List<Long> roleIds) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        user.setSurname(surname);
        user.setAge(age);
        user.setEmail(email);
        validateNewUser(user);
        user.setRoles(resolveRoles(roleIds));
        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
    }

    @Override
    public String regUser(User user) {
        validateNewUser(user);
        String selected = user.getSelectedRole();
        if (!"ADMIN".equals(selected) && !"USER".equals(selected)) selected = "USER";
        Role role = getOrCreateRole("ROLE_" + selected);
        user.setRoles(Set.of(role));
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        userRepository.save(user);
        return "redirect:/login?success";
    }

    @Override
    public void updateUser(User data, List<Long> roleIds) {
        User existing = getUserById(data.getId());
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        User current = userRepository.findByUsername(auth.getName())
                .orElseThrow(() -> new UsernameNotFoundException("Current user not found"));
        boolean isAdmin = current.getRoles().stream()
                .anyMatch(r -> "ROLE_ADMIN".equals(r.getName()));
        if (!isAdmin && !current.getId().equals(existing.getId())) {
            throw new SecurityException("Можно редактировать только свой профиль");
        }
        validateUpdate(existing, data);
        existing.setUsername(data.getUsername());
        existing.setEmail(data.getEmail());
        existing.setSurname(data.getSurname());
        existing.setAge(data.getAge());
        if (data.getPassword() != null && !data.getPassword().isBlank()) {
            if (data.getPassword().length() < 4)
                throw new PasswordException("Пароль должен быть минимум 4 символа");
            if (!isPasswordEncoded(data.getPassword()))
                existing.setPassword(passwordEncoder.encode(data.getPassword()));
            else
                existing.setPassword(data.getPassword());
        }
        if (roleIds != null && !roleIds.isEmpty()) {
            existing.setRoles(resolveRoles(roleIds));
        }
        userRepository.save(existing);
    }

    @Override
    public void contUpdateUser(Long id, String username, String password, String surname, Integer age, String email, List<Long> roleIds) {
        User user = new User();
        user.setId(id);
        user.setUsername(username);
        user.setPassword(password);
        user.setSurname(surname);
        user.setAge(age);
        user.setEmail(email);
        updateUser(user, roleIds);
    }

    @Override
    public boolean existsByUsername(String username) {
        return userRepository.findByUsername(username).isPresent();
    }

    @Override
    public boolean existsByEmail(String email) {
        return userRepository.findByEmail(email).isPresent();
    }

    @Override
    public void deleteUser(Long id) {
        userRepository.deleteById(id);
    }

    @Override
    public void addRoleToUser(Long userId, Role role) {
        User user = getUserById(userId);
        Role managed = roleRepository.findById(role.getId())
                .orElseThrow(() -> new UserRoleException("Role not found"));
        if (user.getRoles().contains(managed))
            throw new UserRoleException("У пользователя уже есть эта роль");
        user.addRole(managed);
        userRepository.save(user);
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(),
                user.getPassword(),
                user.getAuthorities()
        );
    }

    @Override
    public String authUser(Authentication auth) {
        if (auth != null && auth.isAuthenticated()) {
            boolean admin = auth.getAuthorities().stream()
                    .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
            return admin ? "redirect:/admin" : "redirect:/user";
        }
        return "login";
    }
}