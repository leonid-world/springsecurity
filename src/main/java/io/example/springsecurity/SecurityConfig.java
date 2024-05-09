package io.example.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
public class SecurityConfig {
    /**
     * - SecurityContextHolderFilter
     * - SecurityContextRepository
     * 필터가 컨텍스트 객체를 읽어와서 홀더에 설정하는 목적
     * 케이스는 3가지
     * 1. 인증받지 못한상태(익명 사용자)
     * 2. 인증 요청 시점
     * 3. 인증 끝낸 후 후속요청
     *  이 케이스에 대해 필터가 어떤식으로 컨텍스트 객체를 얻은 후 홀더에 설정하는지
     *  초기화과정에서 위 클래스들이 어떻게 생성되고 필터와 어떠한 연관관계를 갖는가?
     */

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/login").permitAll()
                        .anyRequest().authenticated())
                //.formLogin(Customizer.withDefaults())
                //.csrf(csrf -> csrf.disable())
                .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    /**
     * @return
     * CustomService 사용하기
     */
    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user = User.withUsername("user").password("{noop}password").roles("USER").build();
        return new InMemoryUserDetailsManager(user);
        //return new CustomUserDetailsService();
    }
}
