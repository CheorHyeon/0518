package com.ll.rest_api.base.security;

import com.ll.rest_api.base.security.entryPoint.ApiAuthenticationEntryPoint;
import com.ll.rest_api.base.security.filter.JwtAuthorizationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ApiSecurityConfig {
    private final JwtAuthorizationFilter jwtAuthorizationFilter;
    private final ApiAuthenticationEntryPoint authenticationEntryPoint;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .securityMatcher("/api/**") // 아래의 모든 설정은 /api/** 경로에만 적용
                // 인증 진입 지점(인증되지 않은 요청에 대한 응답 처리) 설정
                .exceptionHandling(exceptionHandling -> exceptionHandling
                        .authenticationEntryPoint(authenticationEntryPoint)
                )
                .authorizeHttpRequests(
                        authorizeHttpRequests -> authorizeHttpRequests
                                .requestMatchers(HttpMethod.POST,"/api/*/articles/*").permitAll() // 글 보기는 누구나 가능
                                .requestMatchers(HttpMethod.GET,"/api/*/member/login").permitAll() // 로그인은 누구나 가능
                                .requestMatchers(HttpMethod.GET,"/api/*/articles").permitAll() // 글 보기는 누구나 가능
                                .anyRequest().authenticated() // 나머지는 인증된 사용자만 가능
                )
                .cors().disable() // 타 도메인에서 API 호출 가능
                .csrf().disable() // CSRF 토큰 끄기
                .httpBasic().disable() // httpBaic 로그인 방식 끄기
                .formLogin().disable() // 폼 로그인 방식 끄기
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(STATELESS)
                )
                .addFilterBefore(
                jwtAuthorizationFilter, // 엑세스 토큰으로 부터 로그인 처리
                        // UsernamePassword 필터는 로그인이 안되었을 시 동작하는 필터, 로그인 됐으면 지나감
                UsernamePasswordAuthenticationFilter.class
        );; // 세션끄기


        return http.build();
    }
}