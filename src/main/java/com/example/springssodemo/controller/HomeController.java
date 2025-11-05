package com.example.springssodemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpSession;

@Controller
public class HomeController {

    @GetMapping("/home")
    public String home(HttpSession session, Model model) {
        // Check if user is authenticated via session
        Boolean authenticated = (Boolean) session.getAttribute("authenticated");
        String username = (String) session.getAttribute("username");
        String role = (String) session.getAttribute("role");
        
        // Check if user is logged in
        if (authenticated == null || !authenticated || username == null) {
            return "redirect:/login";
        }
        
        // If ADMIN tries to access /home, redirect to admin dashboard
        if ("ADMIN".equals(role)) {
            return "redirect:/admin-dashboard";
        }
        
        // Regular USER can access home
        model.addAttribute("username", username);
        model.addAttribute("role", role != null ? role : "USER");
        return "home";
    }
}