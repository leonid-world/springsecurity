package io.example.springsecurity;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
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
         * 인증 아키텍쳐
         * 1. 인증 - Authentication
         *     당신은 누구인가? 확인
         *     인증이 수행되면 신원을 알고 권한을 부여할 수 있다.
         *     사용자의 인증 정보를 저장하는 토큰 개념의 객체로 활용된다.
         *     인증 이후 SecurityContext에 저장되어 전역적으로 참조가 가능하다.
         *     Principal 을 상속받고 있다. (자바의 api)
         *          6개 API 존재
         *     - getPrincipal() : 인증 주체를 의미하며 인증 요청의 경우 사용자 이름을, 인증 후 UserDetails 타입의 객체가 될 수 있다.
         *     - getCredentials() : 인증 주제가 올바른 것을 증명하는 자격 증명, 대개 비밀번호를 가져온다. 보통 보안문제로 null로 보관한다.
         *     - getAuthorities() : 인증 주체(principal) 에게 부여된 권한을 나타낸다.
         *     - getDetails() : 인증 요청에 대한 추가적인 세부 사항을 저장한다. IP주소 인증서 일련 번호 등이 될 수 있다.
         *     - isAuthenticated() - 인증 상태 반환 한다.
         *     - setAuthenticated(boolean) : 인증 상태를 설정한다. : true - 인증받음, false - 인증 못받음
         *
         *
         * 2. 보안 컨텍스트 - SecurityContext & SecurityContextHolder
         *     인증을 최종 성공한(인증에 성공) 객체를 보관한다.
         * 3. 인증 관리자 - AuthenticationManager
         *     인증 필터가 인증 시도할 때 가장 먼저 인증 처리를 맡긴다. 그때 Authentication도 인자로 넘어감.
         * 4. 인증 제공자 - AuthenticationProvider
         *     매우 중요한 클래스. AuthenticationManager로부터 인증처리를 위임받는다.
         *     AuthenticationManager는 관리만 하고, 얘가 실제 인증을 총괄한다. 서로 밀접한 관계이지만 보안측에선 이 친구가 실질적인 역할을 한다.
         *       - 로그인 시도한 사용자의 인증정보를 확인한다. (UserDetailsService를 통해 가져온다.)
         * 5. 사용자 상세 서비스 - UserDetailsService
         *     사용자 정보를 가져올 때 서비스를 통해 가져오는데, 미리 UserDetails 를 활용해 사용자정보를 가져올 수 있다.
         * 6. 사용자 상세 - UserDetails
         *     사용자 상세는 UserDetails 에 유저 객체를 담아서 활용할 수 있다.
         */

        /**
         * - DelegatingFilterProxy
         *    : http 요청을 스프링 컨테이너로 넘겨준다. 스프링에서 필터를 사용할 수 있는 다리역할.
         * - FilterChainProxy
         *    : 필터를 하나하나 검사하며 처리
         */

        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setMatchingRequestParameterName("customParam=y");

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
