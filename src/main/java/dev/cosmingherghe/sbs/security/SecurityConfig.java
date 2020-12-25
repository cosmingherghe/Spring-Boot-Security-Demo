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
        String managerPasswd = passwordEncoder().encode("manager");

        managerBuilder
                .inMemoryAuthentication()
                .withUser("user").password(userPasswd).roles("USER")
                .and()
                .withUser("admin").password(adminPasswd).roles("ADMIN")
                .and()
                .withUser("manager").password(managerPasswd).roles("MANAGER");
    }

    //Method to authorise requests
    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/profile/**").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/management/**").hasAnyRole("ADMIN", "MANAGER")
                .and()
                .httpBasic();
    }

    //Use password encoder to
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}