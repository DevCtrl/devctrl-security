package com.devctrl.security.security.handler;

import com.devctrl.security.common.dto.JwtUserDto;
import com.devctrl.security.service.JwtService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;

    @Autowired
    public CustomAuthenticationSuccessHandler(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
                                        HttpServletResponse httpServletResponse,
                                        Authentication authentication) throws IOException, ServletException {
        JwtUserDto jwtUserDto = new JwtUserDto(authentication);

        httpServletResponse.setStatus(HttpServletResponse.SC_CREATED);
        httpServletResponse.getWriter().append(jwtService.generateToken(jwtUserDto)).flush();
    }
}
