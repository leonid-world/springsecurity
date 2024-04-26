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
         * ** AuthenticationManager
         *
         * 인증 필터로부터 Authentication 객체를 전달 받아 인증을 시도하며 인증에 성공할 경우 사용자 정보, 권한 등을 포함한 완전히 채워진 Authentication 객체를 반환한다.
         *  ex) AuthenticationFilter -> Authentication 객체 생성(Username, Password 저장) -> AuthenticationManager에게 인증객체 전달 및 인증처리 위임
         *  -> AuthenticationManager는 내부적으로 인증처리 수행 -> 인증성공? -> Authentication 객체 데이터 보강하여 다시 생성(User객체나 Authority 등 추가됨)
         *  -> AuthenticationFilter로 다시 반환.
         *  이 역할을 AuthenticationManager가 한다.
         *   즉, 인증받기 전 후 과정에서 다리역할을 하는 것
         *
         * AuthenticationManager 는 여러 authenticationProvider 들을 관리하며 AuthenticationProvider 목록을 순차적으로 순회하며 인증 요청을 처리한다.
         * ex ) AuthenticationProvider 클래스들을 가지고 있다.
         * -> 목록 중에서 인증처리요건에 맞는 적절한 Provider를 찾아서 위임한다.
         *
         * AuthenticationProvider 목록 중에서 인증 처리 요건에 맞는 적절한 AuthenticationProvider를 찾아 인증처리를 위임한다.
         * 즉, 인증처리 전 인증객체를 받아서 Provider에 위임하면, 인증성공 후 Authentication 객체를 받아서 Filter에 넘겨준다.
         *
         * AuthenticationManagerBuilder에 의해 객체가 생성되며 주로 사용하는 구현체로 ProviderManager가 제공된다.
         * -> builder 클래스는 AuthenticationManager를 생성하는데, ProviderManager라는 구현체를 사용한다.
         * 즉, ProviderManager는 Provider를 관리하는 객체이다.
         *
         *
         * ** AuthenticationmanagerBuilder
         *
         * AuthenticationManager 객체를 생성하며 UserDetailsService 및 AuthenticationProvider 를 추가할 수 잇다.
         *  -> Builder 클래스를 통해, UserDetailsService 및 AuthenticationProvider를 추가한다.
         *  AuthenticationManager로 직접 Provider를 추가하거나 생성하는것은 아니다. 오직 빌더로만 한다.
         *  Provider를 생성하여, AuthenticationManager로 전달하는 것이다.
         *
         * - 어떻게 참조하는가?
         * HttpSecurity.getSharedObject(AuthenticationManagerBuilder.class) 를 통해 객체를 참조할 수 있다.
         *    !! 참고 : HttpSecurity 는 어떤 자원을 공유할 수 있고 참조할 수 있다.
         *    getSharedObject 에 공유하고자 하는 클래스타입을 주입하면 된다.
         *
         */


        /**
         * AuthenticationManager 사용법 - HttpSecurity 사용
         *
         * AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
         * AuthenticationManager authenticationManager = authenticationManagerbuilder.build();
         * AuthenticationManager authenticationManager = authenticationManagerBuilder.getObject(); // build()는 최초 한번만 호출해야 한다. build() 후에는 getObject() 로 참조해야 한다.
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
