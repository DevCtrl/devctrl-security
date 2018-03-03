package com.devctrl.security.common.dto;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

public class JwtUserDto {
    private String username;
    private String role;

    public JwtUserDto() {
    }

    public JwtUserDto(Authentication authentication) {
        this.role = authentication.getAuthorities().toArray()[0].toString();
        this.username = ((User) authentication.getPrincipal()).getUsername();
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }
}
