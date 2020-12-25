package dev.cosmingherghe.sbs.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //Method that defines data base for users
    @Override
    protected void configure(AuthenticationManagerBuilder managerBuilder) throws Exception {
        String adminPasswd = passwordEncoder().encode("admin");
        String userPasswd = passwordEncoder().encode("user");

        managerBuilder
                .inMemoryAuthentication()
                .withUser("admin").password(adminPasswd).roles("ADMIN")
                .and()
                .withUser("user").password(userPasswd).roles("USER");
    }

    //Method to authorise requests
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .httpBasic();
    }

    //Use password encoder to
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}