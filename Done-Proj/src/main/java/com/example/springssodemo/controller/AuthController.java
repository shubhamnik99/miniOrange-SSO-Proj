package com.example.springssodemo.controller;

import com.example.springssodemo.model.User;
import com.example.springssodemo.repo.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Collections;
import java.util.Optional;

@Controller
public class AuthController {

    private final UserRepository userRepository;

    public AuthController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // ------------------ LOGIN PAGE ------------------
    @GetMapping({"/", "/login"})
    public String loginPage() {
        return "login";
    }

    // ------------------ REGISTER PAGE ------------------
    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    // ------------------ REGISTER USER ------------------
    @PostMapping("/register")
    public String doRegister(@RequestParam String username,
                             @RequestParam String password,
                             @RequestParam String email,
                             @RequestParam(defaultValue = "USER") String role,
                             Model model) {

        // Check if username already exists
        if (userRepository.findByUsername(username).isPresent()) {
            model.addAttribute("error", "Username already exists");
            return "register";
        }

        // Validate role
        if (!role.equalsIgnoreCase("USER") && !role.equalsIgnoreCase("ADMIN")) {
            role = "USER";
        }

        // Save user
        User newUser = new User(username, password, email, role.toUpperCase());
        userRepository.save(newUser);

        model.addAttribute("message", "Registered successfully! Please login.");
        return "login";
    }

    // ------------------ LOGIN ACTION ------------------
    @PostMapping("/doLogin")
    public String doLogin(@RequestParam String username,
                          @RequestParam String password,
                          HttpSession session,
                          Model model) {

        Optional<User> optionalUser = userRepository.findByUsername(username);

        if (optionalUser.isPresent()) {
            User user = optionalUser.get();

            // Validate password
            if (user.getPassword().equals(password)) {

                // Store details in session
                session.setAttribute("username", user.getUsername());
                session.setAttribute("role", user.getRole());
                session.setAttribute("email", user.getEmail());
                session.setAttribute("authenticated", true);

                // Authenticate via Spring Security
                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(
                                user.getUsername(),
                                null,
                                Collections.singletonList(
                                        new SimpleGrantedAuthority("ROLE_" + user.getRole()))
                        );
                SecurityContextHolder.getContext().setAuthentication(authentication);

                // ✅ Redirect based on role
                if ("ADMIN".equalsIgnoreCase(user.getRole())) {
                    return "redirect:/admin-dashboard";
                } else {
                    return "redirect:/home";
                }

            } else {
                model.addAttribute("error", "Invalid password");
                return "login";
            }
        } else {
            model.addAttribute("error", "User not found");
            return "login";
        }
    }

    // ------------------ LOGOUT ------------------
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        SecurityContextHolder.clearContext();
        return "redirect:/login";
    }
}
