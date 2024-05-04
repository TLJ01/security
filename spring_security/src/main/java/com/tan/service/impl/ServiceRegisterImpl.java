package com.tan.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.tan.mapper.MapperUser;
import com.tan.pojo.User;
import com.tan.service.ServiceRegister;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Objects;

/**
 * Created by TanLiangJie
 * Time:2024/5/4 下午10:39
 */
@Service
public class ServiceRegisterImpl implements ServiceRegister {

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



}
