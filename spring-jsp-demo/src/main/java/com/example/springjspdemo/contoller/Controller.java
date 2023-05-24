package com.example.springjspdemo.contoller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@org.springframework.stereotype.Controller
public class Controller {

    @RequestMapping(value = "/login", method= RequestMethod.GET)
    public String loginPage(){
        return "login";
    }
}
