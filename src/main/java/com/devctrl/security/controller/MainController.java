package com.devctrl.security.controller;


import com.devctrl.security.common.dto.GreetingDto;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.concurrent.atomic.AtomicLong;

@RestController
@RequestMapping("/api")
public class MainController  {

    private static final String TEMPLATE = "Hello, %s!";
    private static final String TEMPLATE_ADMIN = "Hello Admin, %s!";
    private final AtomicLong counter = new AtomicLong();

    @PreAuthorize("hasAuthority('ADMIN')")
    @GetMapping("/hello/admin")
    public GreetingDto greetingAdmin(@RequestParam(value = "name", defaultValue = "World") String name) {

        return new GreetingDto(counter.incrementAndGet(),
                String.format(TEMPLATE_ADMIN, name));
    }

    @PreAuthorize("hasAuthority('USER')")
    @GetMapping("/hello/user")
    public GreetingDto greetingUser(@RequestParam(value = "name", defaultValue = "World") String name) {

        return new GreetingDto(counter.incrementAndGet(),
                String.format(TEMPLATE, name));
    }

    @PostMapping("/")
    public GreetingDto homePage(@RequestParam(value = "name", defaultValue = "World") String name) {

        return new GreetingDto(counter.incrementAndGet(),
                String.format(TEMPLATE, name));
    }

    @PreAuthorize("isAuthenticated()")
    @PostMapping({"/user", "/me"})
    public ResponseEntity<?> user(Principal principal) {
        return ResponseEntity.ok(principal);
    }

}
