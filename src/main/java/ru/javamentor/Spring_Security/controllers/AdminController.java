package ru.javamentor.Spring_Security.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import ru.javamentor.Spring_Security.models.User;
import ru.javamentor.Spring_Security.repositories.RoleRepository;
import ru.javamentor.Spring_Security.services.UserService;

import java.util.List;

@Controller
@RequestMapping("/admin")
public class AdminController {

    private final UserService userService;
    private final RoleRepository roleRepository;

    @Autowired
    public AdminController(UserService userService, RoleRepository roleRepository) {
        this.userService = userService;
        this.roleRepository = roleRepository;
    }

    @GetMapping
    public String adminPanel(@AuthenticationPrincipal UserDetails userDetails, Model model) {
        User current = userService.findByUsername(userDetails.getUsername())
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + userDetails.getUsername()));

        model.addAttribute("currentUser", current);
        model.addAttribute("users", userService.getAllUsers());
        model.addAttribute("roles", roleRepository.findAll());
        model.addAttribute("newUser", model.asMap().getOrDefault("newUser", new User()));
        model.addAttribute("tab", model.asMap().getOrDefault("tab", "users"));

        return "admin";
    }

    @PostMapping("/create")
    public String createUser(
            @RequestParam String username,
            @RequestParam String password,
            @RequestParam String surname,
            @RequestParam Integer age,
            @RequestParam String email,
            @RequestParam List<Long> roleIds,
            RedirectAttributes ra) {

        try {
            userService.createUser(username, password, surname, age, email, roleIds);
            return "redirect:/admin";
        } catch (Exception e) {
            ra.addFlashAttribute("createError", e.getMessage());
            ra.addFlashAttribute("tab", "create");

            User failed = new User();
            failed.setUsername(username);
            failed.setSurname(surname);
            failed.setAge(age);
            failed.setEmail(email);
            ra.addFlashAttribute("newUser", failed);

            return "redirect:/admin";
        }
    }

    @GetMapping("/edit/{id}")
    public String editUser(@PathVariable Long id, Model model) {
        model.addAttribute("user", userService.getUserById(id));
        model.addAttribute("allRoles", roleRepository.findAll());
        return "edit";
    }

    @PostMapping("/update")
    public String updateUser(
            @RequestParam Long id,
            @RequestParam String username,
            @RequestParam(required = false) String password,
            @RequestParam(required = false) String surname,
            @RequestParam(required = false) Integer age,
            @RequestParam(required = false) String email,
            @RequestParam List<Long> roleIds,
            RedirectAttributes ra) {

        try {
            userService.contUpdateUser(id, username, password, surname, age, email, roleIds);
            return "redirect:/admin";
        } catch (Exception e) {
            ra.addFlashAttribute("updateError", e.getMessage());
            ra.addFlashAttribute("editUserId", id);
            ra.addFlashAttribute("tab", "edit");
            return "redirect:/admin";
        }
    }

    @PostMapping("/delete/{id}")
    public String deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return "redirect:/admin";
    }
}