package com.devctrl.security.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(value = HttpStatus.UNAUTHORIZED, reason = "Token missing")
public class JwtTokenMissingException  extends AuthenticationException {
    public JwtTokenMissingException(String msg) {
        super(msg);
    }
}