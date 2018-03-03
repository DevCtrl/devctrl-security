package com.devctrl.security.service.impl;

import com.devctrl.security.common.dto.JwtUserDto;
import com.devctrl.security.common.exception.JwtTokenExpiredException;
import com.devctrl.security.config.JwtConfiguration;
import com.devctrl.security.service.JwtService;
import io.jsonwebtoken.*;
import org.joda.time.DateTime;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class JwtServiceImpl implements JwtService {

    private final JwtConfiguration jwtConfiguration;

    @Autowired
    public JwtServiceImpl(JwtConfiguration jwtConfiguration) {
        this.jwtConfiguration = jwtConfiguration;
    }

    @Override
    public String generateToken(JwtUserDto user) {
        Claims claims = Jwts.claims().setSubject(user.getUsername());
        claims.put("role", user.getRole());

        return Jwts.builder()
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, jwtConfiguration.getSecret())
                .setExpiration(DateTime.now().plusSeconds(30).toDate())
                .compact();
    }

    /**
     * Tries to parse specified String as a JWT token. If successful, returns User object with username, id and role prefilled (extracted from token).
     * If unsuccessful (token is invalid or not containing all required user properties), simply returns null.
     *
     * @param token the JWT token to parse
     * @return the User object extracted from specified token or null if a token is invalid.
     */
    @Override
    public JwtUserDto parseToken(String token) {
        JwtUserDto u = null;
        try {
            Claims body = Jwts.parser()
                    .setSigningKey(jwtConfiguration.getSecret())
                    .parseClaimsJws(token)
                    .getBody();

            u = new JwtUserDto();
            u.setUsername(body.getSubject());
            u.setRole((String) body.get("role"));

        } catch (ExpiredJwtException e) {
            throw new JwtTokenExpiredException(e.getMessage());
        } catch (JwtException e) {
            // Simply print the exception and null will be returned for the userDto
            e.printStackTrace();
        }
        return u;
    }

}
