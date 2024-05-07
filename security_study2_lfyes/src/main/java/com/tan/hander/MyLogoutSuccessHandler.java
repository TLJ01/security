package com.tan.hander;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Created by TanLiangJie
 * Time:2024/5/7 上午9:46
 */
public class MyLogoutSuccessHandler implements LogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //返回json
        response.setContentType("application/json;charset=utf-8");
        String data = "{\"code\":200, \"msg\":\"登出成功\", \"data\":{}}";
        response.getWriter().write(data);
    }
}
