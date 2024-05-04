package com.tan.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Created by TanLiangJie
 * Time:2024/5/4 下午2:25
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorizeHttpRequests->
                        authorizeHttpRequests
                                .requestMatchers("/login").permitAll()
//                        .requestMatchers(HttpMethod.POST, "/login").permitAll()
                                .anyRequest().authenticated()
        );
        http.formLogin(formLogin->
                formLogin
                        .loginPage("/mylogin.html")
                        .loginProcessingUrl("/login")
                        .permitAll()
        );
        // 注意 6.2 版本里这里要使用 csrf.disable() 而不是 withDefault() 方法，网上很多使用 withDefault()方法的，个人实践不成功
        http.csrf(csrf->csrf.disable());
        return http.build();
    }




}
