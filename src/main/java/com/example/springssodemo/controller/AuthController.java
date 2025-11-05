package com.example.springssodemo.controller;

import com.example.springssodemo.model.User;
import com.example.springssodemo.repo.UserRepository;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpSession;
import java.util.Collections;

@Controller
public class AuthController {
    private final UserRepository userRepository;

    public AuthController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping({"/", "/login"})
    public String loginPage() {
        return "login";
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/register")
    public String doRegister(@RequestParam String username,
                             @RequestParam String password,
                             @RequestParam String email,
                             @RequestParam(defaultValue = "USER") String role,
                             Model model) {
        if (userRepository.findByUsername(username).isPresent()) {
            model.addAttribute("error", "Username already exists");
            return "register";
        }
        
        // Validate role
        if (!role.equals("USER") && !role.equals("ADMIN")) {
            role = "USER";
        }
        
        User u = new User(username, password, email, role);
        userRepository.save(u);
        model.addAttribute("message", "Registered successfully. Please login.");
        return "login";
    }

    @PostMapping("/doLogin")
    public String doLogin(@RequestParam String username,
                          @RequestParam String password,
                          HttpSession session,
                          Model model) {
        var opt = userRepository.findByUsername(username);
        
        if (opt.isPresent() && opt.get().getPassword().equals(password)) {
            User user = opt.get();
            
            // Store in session
            session.setAttribute("username", username);
            session.setAttribute("role", user.getRole());
            session.setAttribute("email", user.getEmail());
            session.setAttribute("authenticated", true);
            
            // IMPORTANT: Also authenticate with Spring Security
            UsernamePasswordAuthenticationToken authentication = 
                new UsernamePasswordAuthenticationToken(
                    username, 
                    null, 
                    Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
                );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            
            // Role-based redirection
            if ("ADMIN".equals(user.getRole())) {
                return "redirect:/admin-dashboard";
            } else {
                return "redirect:/home";
            }
        } else {
            model.addAttribute("error", "Invalid credentials");
            return "login";
        }
    }
    
    @GetMapping("/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        SecurityContextHolder.clearContext();
        return "redirect:/login";
    }
}