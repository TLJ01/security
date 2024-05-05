package com.tan.controller;

import com.tan.pojo.ResponseResult;
import com.tan.pojo.User;
import com.tan.service.ServiceUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by TanLiangJie
 * Time:2024/5/4 下午2:26
 */
@RequestMapping("/user")
@RestController
public class ControllerUser {

    @Autowired
    private ServiceUser serviceUser;

    /**
     * 登录
     * @param user
     * @return
     */
    @PostMapping("/login")
    public ResponseResult login(@RequestBody User user) {
        return serviceUser.login(user);
    }

    /**
     * 注册
     * @param user
     * @return
     */
    @PostMapping("/register")
    public ResponseResult register(@RequestBody User user) {
        serviceUser.register(user);
        return new ResponseResult(200,"success");
    }


    /**
     * 退出登录
     * @return
     */
    @RequestMapping("/logout")
    public ResponseResult Logout(){
        serviceUser.logout();
        return new ResponseResult(200,"退出成功");
    }



}
