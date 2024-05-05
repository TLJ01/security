package com.tan.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.tan.mapper.MapperUser;
import com.tan.pojo.LoginUser;
import com.tan.pojo.ResponseResult;
import com.tan.pojo.User;
import com.tan.service.ServiceUser;
import com.tan.utils.JwtUtil;
import com.tan.utils.RedisCache;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Objects;

/**
 * Created by TanLiangJie
 * Time:2024/5/5 下午3:38
 */
@Slf4j
@Service
public class ServiceUserImpl implements ServiceUser {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RedisCache redisCache;

    /**
     * 登录
     *
     * @param user
     * @return
     */

    @Override
    public ResponseResult login(User user) {

        //对登录用户进行认证
        UsernamePasswordAuthenticationToken upad = new UsernamePasswordAuthenticationToken(user.getUserName(), user.getPassword());
        Authentication authenticate = authenticationManager.authenticate(upad);

        //不正确,返回错误信息--but认证未通过就出不来，也不报错
        if (Objects.isNull(authenticate)) {
            log.info("密码错误");
            throw new RuntimeException("用户名或者密码错误");
        }

        //获取用户id
        LoginUser loginUser = (LoginUser) authenticate.getPrincipal();
        String userid = loginUser.getUser().getId().toString();

        //正确,存入redis,userid作为key,用户信息作为value
        //authenticate存入redis
        redisCache.setCacheObject("login:" + userid, loginUser);

        //生成jwt
        String jwt = JwtUtil.createJWT(userid);
        HashMap<String, Object> map = new HashMap<>();
        map.put("token", jwt);
        return new ResponseResult(200, "success", map);

    }


    @Autowired
    private MapperUser mapperUser;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * 注册
     * @param registerUser
     */
    @Override
    public void register(User registerUser) {
        //判断该用户是否存在
        LambdaQueryWrapper<User> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(User::getUserName, registerUser.getUserName());
        User user = mapperUser.selectOne(wrapper);

        if (!Objects.isNull(user)){
            //存在,抛出错误信息
            throw new RuntimeException("用户名已经存在");
        }

        //不存在,存入数据库
        //加密
        String encode = passwordEncoder.encode(registerUser.getPassword());
        registerUser.setPassword(encode);
        mapperUser.insert(registerUser);
    }


    /**
     * 退出登录
     */
    @Override
    public void logout() {

        //获取用户信息
        UsernamePasswordAuthenticationToken authentication = (UsernamePasswordAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        //获取userid
        LoginUser loginUser = (LoginUser) authentication.getPrincipal();
        String userid = loginUser.getUser().getId().toString();
        //删除redis中的用户信息
        String key = "login:"+userid;
        redisCache.deleteObject(key);
    }

}
