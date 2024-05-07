package com.tan.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by TanLiangJie
 * Time:2024/5/6 上午9:51
 */
@RestController
public class ControllerHello {

    @GetMapping("/hello")
    public String hello(){
        return "hello";
    }

    /**
     * 登录成功
     * @return
     */
    @RequestMapping("/success")
    public String success(){
        return "success";
    }

    /**
     * 登录失败
     * @return
     */
    @RequestMapping("/fail")
    public String fail(){
        return "fail";
    }


    @RequestMapping("/logoutsuccess")
    public String logout(){
        return "logoutsuccess";
    }

}
