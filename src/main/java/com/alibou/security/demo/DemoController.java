package com.alibou.security.demo;

import com.alibou.security.config.JwtService;
import com.alibou.security.user.User;
import com.alibou.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
@CrossOrigin(origins = "*",allowedHeaders = "*")
@RestController
@RequestMapping("/api/v1/demo-controller")
@RequiredArgsConstructor
public class DemoController {
    private final JwtService jwtService;
    @Autowired
    UserRepository userRepository;
    @GetMapping
    public ResponseEntity<String> sayHello(Authentication authentication){
        Optional<User> user = userRepository.findByEmail(authentication.getName());
        return ResponseEntity.ok(user.get().getFirstname());
    }
}
