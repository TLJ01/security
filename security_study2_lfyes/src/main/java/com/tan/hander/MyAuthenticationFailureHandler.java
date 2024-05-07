package com.tan.hander;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by TanLiangJie
 * Time:2024/5/7 上午9:39
 */

public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        response.setContentType("application/html;charset=utf-8");
        //返回json
        response.setContentType("application/json;charset=utf-8");
        String data = "{\"code\":500, \"msg\":\"登录失败\", \"data\":{\"error\":"+exception.getMessage()+"}}";
        response.getWriter().write(data);

    }
}
