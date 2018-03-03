package com.devctrl.security.config;

import com.devctrl.security.security.JwtAuthenticationEntryPoint;
import com.devctrl.security.security.JwtAuthenticationProvider;
import com.devctrl.security.security.JwtAuthenticationSuccessHandler;
import com.devctrl.security.security.JwtAuthenticationTokenFilter;
import com.devctrl.security.security.handler.CustomAuthenticationFailureHandler;
import com.devctrl.security.security.handler.CustomAuthenticationSuccessHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtConfiguration jwtConfiguration;
    private final JwtAuthenticationEntryPoint unauthorizedHandler;
    private final JwtAuthenticationProvider authenticationProvider;
    private final CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    public WebSecurityConfig(JwtConfiguration jwtConfiguration,
                             JwtAuthenticationEntryPoint unauthorizedHandler,
                             JwtAuthenticationProvider authenticationProvider,
                             CustomAuthenticationSuccessHandler customAuthenticationSuccessHandler) {
        this.jwtConfiguration = jwtConfiguration;
        this.unauthorizedHandler = unauthorizedHandler;
        this.authenticationProvider = authenticationProvider;
        this.customAuthenticationSuccessHandler = customAuthenticationSuccessHandler;
    }

    @Bean
    public JwtAuthenticationTokenFilter authenticationTokenFilterBean() throws Exception {
        JwtAuthenticationTokenFilter authenticationTokenFilter = new JwtAuthenticationTokenFilter(jwtConfiguration.getHeader());
        authenticationTokenFilter.setAuthenticationManager(authenticationManager());
        authenticationTokenFilter.setAuthenticationSuccessHandler(new JwtAuthenticationSuccessHandler());
        return authenticationTokenFilter;
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                // we don't need CSRF because our token is invulnerable
                .csrf().disable()
                // All urls must be authenticated (filter for token always fires (/api/**)
                .authorizeRequests().antMatchers("/api/**").authenticated()
                .and()
                // Call our errorHandler if authentication/authorisation fails
                .exceptionHandling()
                .authenticationEntryPoint(unauthorizedHandler)
                .and()
                // don't create session (REST)
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        // Custom JWT based security filter
        httpSecurity
                .addFilterBefore(authenticationTokenFilterBean(), UsernamePasswordAuthenticationFilter.class);

        // disable page caching
        httpSecurity.headers().cacheControl();

        httpSecurity
                .formLogin()
                .loginProcessingUrl("/loginForm")
                .successHandler(customAuthenticationSuccessHandler)
                .failureHandler(new CustomAuthenticationFailureHandler());
    }

    @Autowired
    public void configureAuthentication(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        //Default users to grant access
        authenticationManagerBuilder
                .inMemoryAuthentication() // TODO: 04.03.18 move this to properties
                .withUser("user").password("test123").authorities("USER").and()
                .withUser("admin").password("test123").authorities("ADMIN");

        authenticationManagerBuilder.authenticationProvider(authenticationProvider);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

}
