package com.tan.config;

import com.tan.hander.MyAuthenticationFailureHandler;
import com.tan.hander.MyAuthenticationSuccessHandler;
import com.tan.hander.MyLogoutSuccessHandler;
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
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.firewall.StrictHttpFirewall;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

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
                .antMatchers("/userLogin").permitAll()
                //登录成功不用配置,失败需要,否则被拦截
                .antMatchers("/fail").permitAll()
                //登出
                .antMatchers("/logoutsuccess").permitAll()
                //其他的都需要拦截
                .anyRequest().authenticated();

        //用户登录控制
        http.formLogin()
                .loginProcessingUrl("/userLogin")
                .loginPage("/login.html")
                .successForwardUrl("/success")//登录成功跳转
                .failureForwardUrl("/fail")//失败跳转

                /**
                 * 后面的会覆盖前面的
                 */
                .successHandler(new MyAuthenticationSuccessHandler())//登录成功返回json信息
                .failureHandler(new MyAuthenticationFailureHandler())
        ;


        //用户登出
        http.logout()
                .logoutUrl("/userLogout")
                .logoutSuccessUrl("/logoutsuccess")
                .logoutSuccessHandler(new MyLogoutSuccessHandler())


        ;
    }


    /**
     *解决乱码
     * http请求header中包含中文字符时，Spring Security识别为乱码并拦截报错
     * @return
     */
    @Bean
    public StrictHttpFirewall httpFirewall() {
        StrictHttpFirewall firewall = new StrictHttpFirewall();
        firewall.setAllowedHeaderNames((header) -> true);
        firewall.setAllowedHeaderValues((header) -> true);
        firewall.setAllowedParameterNames((parameter) -> true);
        return firewall;
    }


}
