package com.github.TheTrueHooha.OAuth.Security.Implementation.ResourceServer.Controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class UserController {

    @GetMapping("/all-users")
    public String[] getAllUsers() {
        return new String[]{
                "michael is my name",
                "welcome to my world",
                "My God is interstellar"
        };
    }
}
