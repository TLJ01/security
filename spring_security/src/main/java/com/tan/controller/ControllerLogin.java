package com.tan.controller;

import com.tan.pojo.ResponseResult;
import com.tan.pojo.User;
import com.tan.service.ServiceLogin;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by TanLiangJie
 * Time:2024/5/4 下午2:26
 */
@RestController
public class ControllerLogin {

    @Autowired
    private ServiceLogin serviceLogin;

    @PostMapping("/user/login")
    public ResponseResult login(@RequestBody User user) {
        return serviceLogin.login(user);
    }

}
