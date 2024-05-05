package com.tan.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.tan.mapper.MapperUser;
import com.tan.pojo.LoginUser;
import com.tan.pojo.User;
import com.tan.service.ServiceUserDetails;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Created by TanLiangJie
 * Time:2024/5/4 下午2:13
 */
@Service
public class ServiceUserDetailsImpl implements UserDetailsService {

    @Autowired
    private MapperUser mapperUser;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //根据用户名获取用户信息
        LambdaQueryWrapper<User> queryWrapper = new LambdaQueryWrapper<>();
        queryWrapper.eq(User::getUserName,username);
        User user = mapperUser.selectOne(queryWrapper);
        //用户不存在，返回错误信息
        if (Objects.isNull(user)){
            throw new RuntimeException("该用户不存在");
        }
        //  用户存在,查询用户权限
        List<String> list = new ArrayList<>(Arrays.asList("test","admin"));

        //封装为UserDetails并返回
        /**
         * UserDetails 是个接口,需要写一个它的实现类
         */
        return new LoginUser(user,list);
    }
}
