package com.tan.service;

import com.tan.pojo.ResponseResult;
import com.tan.pojo.User;

public interface ServiceUser {

    /**
     * 登录
     * @param user
     * @return
     */
    ResponseResult login(User user);

    /**
     * 注册
     * @param user
     */
    void register(User user);


    /**
     * 退出登录
     */
    void logout();
}
