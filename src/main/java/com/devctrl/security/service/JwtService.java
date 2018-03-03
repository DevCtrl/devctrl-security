package com.devctrl.security.service;

import com.devctrl.security.common.dto.JwtUserDto;

public interface JwtService {
    String generateToken(JwtUserDto user);
    JwtUserDto parseToken(String token);
}
