package com.gauri.generateToken.controller;

import com.gauri.generateToken.entity.User;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/user")
public class UserController {

    @GetMapping("/test")
    public ResponseEntity<?> test() {

        return ResponseEntity.ok(
                Map.of("message","Access granted! Token is valid"));
    }

//    @GetMapping
//    public User getUser() {
//        return User;
//    }
}
