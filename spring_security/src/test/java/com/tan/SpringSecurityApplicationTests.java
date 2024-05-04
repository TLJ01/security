package com.tan;

import com.tan.mapper.MapperUser;
import com.tan.pojo.User;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.List;

@SpringBootTest
class SpringSecurityApplicationTests {


    @Autowired
    private MapperUser mapperUser;

    @Test
    void contextLoads() {
        List<User> users = mapperUser.selectList(null);
        System.out.println(users);
    }

}
