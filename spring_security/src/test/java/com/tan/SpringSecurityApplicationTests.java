package com.tan;

import com.tan.mapper.MapperUser;
import com.tan.pojo.User;
import com.tan.utils.Md5Util;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.List;

@SpringBootTest
class SpringSecurityApplicationTests {


    @Autowired
    private MapperUser mapperUser;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Test
    void contextLoads() {
        List<User> users = mapperUser.selectList(null);
        System.out.println(users);
    }
    @Test
    void PasswordTest(){
        System.out.println(passwordEncoder.matches("1234","$2a$10$muREvH4CgH2LSlg9qbYWkO26dDAeOhg8tmDeh1kbE6/1WbObkxqKC"));
    }


    @Test
    void Md5(){
        System.out.println(Md5Util.getMD5String("1234"));
    }
}
