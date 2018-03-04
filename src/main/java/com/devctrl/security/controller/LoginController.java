package com.devctrl.security.controller;

import com.devctrl.security.common.dto.JwtUserDto;
import com.devctrl.security.common.dto.LoginDto;
import com.devctrl.security.security.JwtAuthenticationProvider;
import com.devctrl.security.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.springframework.http.ResponseEntity.status;

@RestController
@RequestMapping("/login")
public class LoginController {

    private final JwtService jwtService;
    private final JwtAuthenticationProvider authenticationManager;

    @Autowired
    public LoginController(JwtService jwtService,
                           JwtAuthenticationProvider authenticationManager) {
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
    }


    @PostMapping
    public ResponseEntity login(@RequestBody LoginDto dto) {
        Authentication authentication = authenticationManager
                .authenticate(new UsernamePasswordAuthenticationToken(
                        dto.getUsername(),
                        dto.getPassword()));

        return isAuthenticated(authentication)
                ? status(HttpStatus.CREATED).body(jwtService.generateToken(new JwtUserDto(authentication)))
                : status(HttpStatus.UNAUTHORIZED).build();
    }

    private boolean isAuthenticated(Authentication authentication) {
        return authentication != null &&
            !(authentication instanceof AnonymousAuthenticationToken) &&
            authentication.isAuthenticated();
    }
}
