package com.jay.security.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Slf4j
@Configuration
public class SecurityConfig {

  // Dummy users. Add LDAP configuration here
  @Bean
  public InMemoryUserDetailsManager userDetailsService() {
    UserDetails user = User.withUsername("user")
        .password(passwordEncoder().encode("pass"))
        .roles("USER")
        .build();

    UserDetails admin = User.withUsername("admin")
        .password(passwordEncoder().encode("pass"))
        .roles("ADMIN")
        .build();

    return new InMemoryUserDetailsManager(user, admin);
  }

  // Password encoder
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http.csrf(AbstractHttpConfigurer::disable)
        .authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> authorizationManagerRequestMatcherRegistry
                .requestMatchers("/anonymous*").anonymous()
                .requestMatchers("/login*", "/invalidSession*", "/sessionExpired*", "/foo/**").permitAll()
                .anyRequest().authenticated())
        .formLogin(httpSecurityFormLoginConfigurer -> httpSecurityFormLoginConfigurer
            .loginProcessingUrl("/login")
            .successHandler(new CustomAuthenticationSuccessHandler())
            .failureUrl("/login?error=true"))
        .logout(httpSecurityLogoutConfigurer -> httpSecurityLogoutConfigurer
            .deleteCookies("JSESSIONID"))
        .rememberMe(httpSecurityRememberMeConfigurer -> httpSecurityRememberMeConfigurer
            .key("uniqueAndSecret")
            .tokenValiditySeconds(86400))
        .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer
                .sessionFixation()
                .migrateSession().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl("/invalidSession")
                .maximumSessions(1) // Max number of sessions
                .expiredUrl("/sessionExpired"))
        .build();
  }
}
