package com.tan.hander;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by TanLiangJie
 * Time:2024/5/7 上午9:19
 */
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {


        //保证不乱码
        response.setContentType("application/json;charset=utf-8");
        String data = "{\"code\":200, \"msg\":\"登录成功\", \"data\":{}}";
        response.getWriter().write(data);

    }
}
