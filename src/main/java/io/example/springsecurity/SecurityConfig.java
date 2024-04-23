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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        http
            .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
            .formLogin(form -> form
                    //.loginPage("/loginPage")
                    .loginProcessingUrl("/loginProc")
                    .defaultSuccessUrl("/", true)
                    .failureUrl("/failed")
                    .usernameParameter("userId")
                    .passwordParameter("passwd")
                    .successHandler((request,response,authentication) -> {
                        //defaultSuccessUrl 보다 더 우선순위가 높음. Success Url 을 더 세심하게 설정하고 싶으면 여기서 설정
                            System.out.println("authentication : " + authentication);
                            response.sendRedirect("/home");
                    })
                    .failureHandler((request,response, exception) -> {
                        System.out.println("exception: " + exception.getMessage());
                        response.sendRedirect("/login");
                    })
                    .permitAll()
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
