package com.example.springssodemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           RelyingPartyRegistrationRepository relyingPartyRegistrationRepository)
            throws Exception {

        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/login", "/jwt/**", "/oauth2/**", "/saml2/**", "/css/**", "/js/**").permitAll()
                    .anyRequest().authenticated()
            )
            // ✅ SAML SSO
            .saml2Login(saml2 -> saml2
                    .loginPage("/login")
                    .defaultSuccessUrl("/saml2/callback", true)
                    .relyingPartyRegistrationRepository(relyingPartyRegistrationRepository)
            )
            // ✅ OIDC/OAuth2 SSO
            .oauth2Login(oauth2 -> oauth2
                    .loginPage("/login")
                    .defaultSuccessUrl("/oauth2/callback", true)
            )
            // ✅ No basic/form login
            .formLogin(form -> form.disable())
            .httpBasic(basic -> basic.disable())
            .logout(logout -> logout
                    .logoutUrl("/logout")
                    .logoutSuccessUrl("/login?logout=true")
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID")
            );

        return http.build();
    }
}
