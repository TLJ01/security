package com.tan.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Created by TanLiangJie
 * Time:2024/5/6 上午9:53
 */
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {


    @Bean
    public UserDetailsService userDetailsService() {
        //将用户密码存在内存中进行测试
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("always").password("123456").authorities("p1").build());
        manager.createUser(User.withUsername("tantan").password("123456").authorities("p2").build());
        return manager;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        //密码不加密
        return NoOpPasswordEncoder.getInstance();
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //关闭csrf
        http.csrf().disable();

        //请求url权限控制
        http.authorizeRequests()
                .antMatchers("/login.html").permitAll()
                //放行
                .antMatchers("/login").permitAll()
                //其他的都需要拦截
                .anyRequest().authenticated();

        //用户登录控制
        http.formLogin()
                .loginProcessingUrl("/userLogin")
                .loginPage("/login.html");
    }
}
