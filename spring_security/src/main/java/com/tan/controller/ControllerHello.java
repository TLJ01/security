package com.tan.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Created by TanLiangJie
 * Time:2024/5/4 下午1:55
 */

@RestController
public class ControllerHello {

    @GetMapping("/hello")
    @PreAuthorize("hasAuthority('test')")
    public String hello() {
        return "Hello World";
    }

}
