package com.tan.service;

import com.tan.pojo.ResponseResult;
import com.tan.pojo.User;

public interface ServiceLogin {
    /**
     * 登录
     * @param user
     * @return
     */
    ResponseResult login(User user);
}
