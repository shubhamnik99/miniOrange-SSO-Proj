package com.example.springssodemo.controller;

import com.example.springssodemo.model.User;
import com.example.springssodemo.repo.UserRepository;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpSession;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Controller
public class DashboardController {
    
    private final UserRepository userRepository;

    public DashboardController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // Removed /home mapping - it's handled by HomeController

    @GetMapping("/admin-dashboard")
    public String adminDashboard(HttpSession session, Model model) {
        // Check if user is authenticated via session
        Boolean authenticated = (Boolean) session.getAttribute("authenticated");
        String username = (String) session.getAttribute("username");
        String role = (String) session.getAttribute("role");
        
        if (authenticated == null || !authenticated || username == null) {
            return "redirect:/login";
        }
        
        // Only allow ADMIN role
        if (!"ADMIN".equals(role)) {
            return "redirect:/home";
        }
        
        model.addAttribute("username", username);
        model.addAttribute("role", role);
        return "admin-dashboard";
    }
    
    // ==================== CRUD API ENDPOINTS ====================
    
    // GET all users
    @GetMapping("/api/users")
    @ResponseBody
    public ResponseEntity<List<User>> getAllUsers(HttpSession session) {
        // Check authentication
        Boolean authenticated = (Boolean) session.getAttribute("authenticated");
        String role = (String) session.getAttribute("role");
        
        if (authenticated == null || !authenticated || !"ADMIN".equals(role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(List.of());
        }
        
        return ResponseEntity.ok(userRepository.findAll());
    }
    
    // GET user stats
    @GetMapping("/api/users/stats")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> getUserStats(HttpSession session) {
        // Check authentication
        Boolean authenticated = (Boolean) session.getAttribute("authenticated");
        String role = (String) session.getAttribute("role");
        
        if (authenticated == null || !authenticated || !"ADMIN".equals(role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of());
        }
        
        List<User> users = userRepository.findAll();
        Map<String, Object> stats = new HashMap<>();
        
        stats.put("total", users.size());
        stats.put("admins", users.stream().filter(u -> "ADMIN".equals(u.getRole())).count());
        stats.put("users", users.stream().filter(u -> "USER".equals(u.getRole())).count());
        
        return ResponseEntity.ok(stats);
    }
    
    // GET single user by ID
    @GetMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> getUserById(@PathVariable Long id, HttpSession session) {
        // Check authentication
        Boolean authenticated = (Boolean) session.getAttribute("authenticated");
        String role = (String) session.getAttribute("role");
        
        if (authenticated == null || !authenticated || !"ADMIN".equals(role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
        }
        
        Optional<User> user = userRepository.findById(id);
        if (user.isPresent()) {
            return ResponseEntity.ok(user.get());
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
    }
    
    // CREATE new user
    @PostMapping("/api/users")
    @ResponseBody
    public ResponseEntity<?> createUser(@RequestBody User user, HttpSession session) {
        // Check authentication
        Boolean authenticated = (Boolean) session.getAttribute("authenticated");
        String role = (String) session.getAttribute("role");
        
        if (authenticated == null || !authenticated || !"ADMIN".equals(role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
        }
        
        // Validate input
        if (user.getUsername() == null || user.getUsername().trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username is required");
        }
        
        if (user.getEmail() == null || user.getEmail().trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email is required");
        }
        
        if (user.getPassword() == null || user.getPassword().trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Password is required");
        }
        
        // Check if username already exists
        if (userRepository.findByUsername(user.getUsername()).isPresent()) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }
        
        // Set default role if not provided
        if (user.getRole() == null || user.getRole().trim().isEmpty()) {
            user.setRole("USER");
        }
        
        // Validate role
        if (!user.getRole().equals("USER") && !user.getRole().equals("ADMIN")) {
            user.setRole("USER");
        }
        
        User savedUser = userRepository.save(user);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedUser);
    }
    
    // UPDATE existing user
    @PutMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> updateUser(@PathVariable Long id, @RequestBody User updatedUser, HttpSession session) {
        // Check authentication
        Boolean authenticated = (Boolean) session.getAttribute("authenticated");
        String role = (String) session.getAttribute("role");
        
        if (authenticated == null || !authenticated || !"ADMIN".equals(role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
        }
        
        Optional<User> existingUserOpt = userRepository.findById(id);
        if (!existingUserOpt.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
        
        User existingUser = existingUserOpt.get();
        
        // Validate input
        if (updatedUser.getUsername() == null || updatedUser.getUsername().trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Username is required");
        }
        
        if (updatedUser.getEmail() == null || updatedUser.getEmail().trim().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Email is required");
        }
        
        // Check if new username conflicts with another user
        Optional<User> userWithSameUsername = userRepository.findByUsername(updatedUser.getUsername());
        if (userWithSameUsername.isPresent() && !userWithSameUsername.get().getId().equals(id)) {
            return ResponseEntity.status(HttpStatus.CONFLICT).body("Username already exists");
        }
        
        // Update fields
        existingUser.setUsername(updatedUser.getUsername());
        existingUser.setEmail(updatedUser.getEmail());
        
        // Only update password if provided
        if (updatedUser.getPassword() != null && !updatedUser.getPassword().trim().isEmpty()) {
            existingUser.setPassword(updatedUser.getPassword());
        }
        
        // Update role
        if (updatedUser.getRole() != null && !updatedUser.getRole().trim().isEmpty()) {
            if (updatedUser.getRole().equals("USER") || updatedUser.getRole().equals("ADMIN")) {
                existingUser.setRole(updatedUser.getRole());
            }
        }
        
        User savedUser = userRepository.save(existingUser);
        return ResponseEntity.ok(savedUser);
    }
    
    // DELETE user
    @DeleteMapping("/api/users/{id}")
    @ResponseBody
    public ResponseEntity<?> deleteUser(@PathVariable Long id, HttpSession session) {
        // Check authentication
        Boolean authenticated = (Boolean) session.getAttribute("authenticated");
        String role = (String) session.getAttribute("role");
        String currentUsername = (String) session.getAttribute("username");
        
        if (authenticated == null || !authenticated || !"ADMIN".equals(role)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Access denied");
        }
        
        Optional<User> userOpt = userRepository.findById(id);
        if (!userOpt.isPresent()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("User not found");
        }
        
        User user = userOpt.get();
        
        // Prevent admin from deleting themselves
        if (user.getUsername().equals(currentUsername)) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("You cannot delete your own account");
        }
        
        userRepository.deleteById(id);
        return ResponseEntity.ok("User deleted successfully");
    }
}