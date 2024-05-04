package com.tan.controller;

import com.tan.pojo.ResponseResult;
import com.tan.pojo.User;
import com.tan.service.ServiceRegister;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by TanLiangJie
 * Time:2024/5/4 下午10:37
 */
@RestController
public class ControllerRegister {

    @Autowired
    private ServiceRegister serviceRegister;

    @PostMapping("/register")
    public ResponseResult register(@RequestBody User user) {
        serviceRegister.register(user);
        return new ResponseResult(200,"success");
    }

}
