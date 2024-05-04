package com.tan.service.impl;

import com.tan.pojo.LoginUser;
import com.tan.pojo.ResponseResult;
import com.tan.pojo.User;
import com.tan.service.ServiceLogin;
import com.tan.utils.JwtUtil;
import lombok.extern.java.Log;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Objects;

/**
 * Created by TanLiangJie
 * Time:2024/5/4 下午2:28
 */
@Service
public class ServiceLoginImpl implements ServiceLogin {

    //EnableWebSercurity做的
    @Autowired
    private AuthenticationManager authenticationManager;


    /**
     * 登录
     * @param user
     * @return
     */

    @Override
    public ResponseResult login(User user) {
        //对登录用户进行认证
        UsernamePasswordAuthenticationToken upad = new UsernamePasswordAuthenticationToken(user.getUserName(),user.getPassword());
        Authentication authenticate = authenticationManager.authenticate(upad);
        //不正确,返回错误信息
        if (Objects.isNull(authenticate)){
            throw new RuntimeException("用户名或者密码错误");
        }

        //正确,存入redis,userid作为key,用户信息作为value
        //获取用户id
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        String userid = loginUser.getUser().getId().toString();

        //生成jwt
        String jwt = JwtUtil.createJWT(userid);
        HashMap<String, Object> map = new HashMap<>();
        map.put("token", jwt);
        return new ResponseResult(200,"success",map);
    }
}
