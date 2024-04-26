package io.example.springsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        /**
         * ** AuthenticationProvider : AuthenticationManager 로부터 인증을 위임받는 객체
         * 사용자의 자격 증명을 확인하고 인증 과정을 관리하는 클래스로서 사용자가 시스템에 액세스하기 위해 제공한 정보(예: 아이디 비밀번호) 가 유효한지 검증하는 과정이다.
         * 다양한 유형의 인증 메커니즘을 지원할 수 있는데, 예를 들어 표준 사용자 이름과 비밀번호를 기반으로 한 인증, 토큰기반인증, 지문인식 등을 처리할 수 있다.
         *    그래서, 인증과정은 이 클래스를 통해 구현한다.
         * 성공적인 인증 후 Authentication 객체를 반환하며 이 객체에는 사용자의 신원 정보와 인증된 자격 증명을 포함한다.
         * 인증 과정 중에 문제가 발생한 경우 AuthenticationException 과 같은 예외를 발생시켜 문제를 알리는 역할을 한다.
         *
         * AuthenticationProvider 도 interface 이다.
         *  - authenticate(Authentication) : AuthenticationManager로붵 Authentication 객체를 전달 받아 인증을 수행한다.
         *  - supports(Class<?>) : 인증을 수행할 수 있는 조건인지 검사한다. true 가 되어야 현재 provider가 인증을 수행하게 된다.
         *
         * AuthenticationProvider 흐름
         *  1. AuthenticationManager 로부터 Authentication(username, password) 를 전달받음
         *  2. AuthenticationProvider 의 authentication() 으로 인증을 수행
         *   -> 사용자 유무 검증, 비밀번호 검증, 보안 강화 처리 등을 실행한다.
         *    즉 이 메서드로 사용자에 대한 모든 검증을 마치고 인증성공여부를 가린다.
         *  3. 성공시 : Authentication 에 UserDetails + Authorities 를 담아 반환한다.
         *     실패시 : AuthenticationException 예외를 발생시킨다.
         */

        http
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/logoutSuccess").permitAll()
                    .anyRequest().authenticated())
            .formLogin(Customizer.withDefaults()
            );

        return http.build();
    }

    /**
     * @return
     * 인메모리 방식으로 계정 만들기
     */
    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user = User.withUsername("user")
            .password("{noop}1111")
                .roles("USER").build();

        return new InMemoryUserDetailsManager(user);
    }
}
