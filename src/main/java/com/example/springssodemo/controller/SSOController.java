package com.example.springssodemo.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.springssodemo.model.User;
import com.example.springssodemo.repo.UserRepository;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.Optional;

@Controller
public class SSOController {

    private final UserRepository userRepository;

    public SSOController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // ✅ OIDC/OAuth2 callback (working already)
    @GetMapping("/oauth2/callback")
    public String oauthCallback(HttpSession session) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.getPrincipal() instanceof OAuth2User oauthUser) {

            String username = oauthUser.getAttribute("email");
            if (username == null) username = oauthUser.getAttribute("login");
            if (username == null) username = oauthUser.getAttribute("name");
            if (username == null) username = oauthUser.getName();

            String email = oauthUser.getAttribute("email");
            if (email == null) email = username + "@example.com";

            User user = findOrCreateUser(username, email);

            session.setAttribute("username", user.getUsername());
            session.setAttribute("email", user.getEmail());
            session.setAttribute("role", user.getRole());
            session.setAttribute("authenticated", true);
            session.setAttribute("authMethod", "OAuth2");

            if ("ADMIN".equals(user.getRole())) {
                return "redirect:/admin-dashboard";
            } else {
                return "redirect:/home";
            }
        }
        return "redirect:/login?error=oauth_failed";
    }

    // ✅ JWT callback handler
    @GetMapping("/jwt/callback")
    public String jwtCallback(@RequestParam("token") String token, HttpSession session) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            String username = jwt.getClaim("sub").asString();
            String email = jwt.getClaim("email").asString();

            if (username == null) username = jwt.getClaim("name").asString();
            if (email == null) email = username + "@example.com";

            User user = findOrCreateUser(username, email);

            session.setAttribute("username", user.getUsername());
            session.setAttribute("email", user.getEmail());
            session.setAttribute("role", user.getRole());
            session.setAttribute("authenticated", true);
            session.setAttribute("authMethod", "JWT");

            if ("ADMIN".equals(user.getRole())) {
                return "redirect:/admin-dashboard";
            } else {
                return "redirect:/home";
            }

        } catch (Exception e) {
            e.printStackTrace();
            return "redirect:/login?error=jwt_failed";
        }
    }

    private User findOrCreateUser(String username, String email) {
        Optional<User> existingUser = userRepository.findByUsername(username);
        if (existingUser.isPresent()) {
            return existingUser.get();
        }
        User newUser = new User();
        newUser.setUsername(username);
        newUser.setEmail(email);
        newUser.setPassword("SSO_AUTH");
        newUser.setRole("USER");
        return userRepository.save(newUser);
    }
}
