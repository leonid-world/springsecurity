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
         *
         * *** SecurityContext ***
         * - Authentication 저장 : 현재 인증된 사용자의 Authentication 객체를 저장하는 저장소
         * - ThreadLocal 저장소 : SecurityContextHolder를 통해 접근되며 ThreadLocal에 Context가 저장되는데, 이 ThreadLocal 저장소를 사용해 각 스레드가 자신만의 보안 컨텍스트를 유지한다.
         *   ex) client 3명일 때, 서버는 client 마다 스레드를 생성한다. 이 스레드가 client의 요청을 처리한다. 이 스레드마다 ThreadLocal 이란 독립적인 저장소를 갖고있다.
         *       이 ThreadLocal에 SecurityContext 값이 저장된다. 즉, client 마다 스레드가 생성되고 스레드마다 스레드로컬이 있고 스레드로컬에 컨텍스트루트가 있다는 것은, 독립적으로 컨텍스트루트 객체를 갖고있다.
         *       각각은 독립적이기 때문에 다른 스레드의 값을 가져오거나 저장할 순 없다. 자기만의 Authentication 객체만 참고할 수 있기 때문에, 자신만의 보안 컨텍스트를 유지한다고 볼 수 있다.
         *
         * - 애플리케이션 전반에 걸친 접근성 : 애플리케이션의 어느 곳에서나 접근 가능하고 현재 사용자의 인증 상태나 권한을 확인하는 데 사용된다.
         *
         *  SecurityContext 참조 : SecurityContextHolder.getContextHolderStrategy().getContext()
         *  SecurityContext 삭제 : SecurityContextHolder.getContextHolderStrategy().clearContext()
         *
         * **************** 자바 동시성 문제 ***********************
         *  스레드 풀에서 운용되는 스레드는, 새로운 요청이더라도 기존의 ThreadLocal이 재사용될 수 있기 때문에 클라이언트로 응답 직전에 항상 SecurityContext를 삭제 해 줘야 한다.
         *  스레드는 재사용되는데, Client1에게 할당된 스레드가 요청을 수행한 후, Client4에게 할당될 수 있기 때문에, Authentication 정보는 삭제해야 한다.
         *  그래서, 매번 ThreadLocal 의 SecurityContext는 다시 인증을 수행한다.
         *  만약, 요청이 들어올 때마다 스레드풀의 스레드가 추가로 생성된다면 초기화할 필요가 없긴 하다.
         *
         *
         * *** SecurityContextHolder
         * - SecurityContext 저장 : 현재 인증된 사용자의 Authentication 객체를 담고 있는 SecurityContext객체를 저장한다.
         *    ex) SecurityContext 객체를 저장하는 방식은 3가지가 있다. 다양한 저장 전략을 지원하기 위해 전략패턴이 사용된다.
         * - 전략 패턴 사용 : 다양한 저장 전략을 지원하기 위해 SecurityContextHolderStrategy 인터페이스를 사용한다.
         * - 기본 전략 : MODE_THREADLOCAL 특정 전략을 지정하지 않으면, 이 전략이 디폴트가 된다.
         * - 전략 모드 직접 설정 : SecurityContextHOlder.setStrategyName(String 전략이름) 전략모드를 직접 설정하고 싶다면...
         *      그리고 전략들은 각각 다른 Strategy 구현체를 생성한다.
         *
         *   ** 구조 **
         *   - SecurityContextHolderStrategy
         *    setDeferredContext : 현재 컨텍스트를 반환하는 Supplier를 저장한다. (바로 메모리에서 가져오는것이 아니라, Supplier 에 저장해놓고 필요시 가져오기 때문에, 지연이 발생한다.)
         *    createEmptyContext
         *    getContext
         *    clearContext
         *    setContext
         *    getDeferredContext : 현재 컨텍스트를 반환하는 Supplier를 얻는다.(바로 메모리에서 가져오는것이 아니라, Supplier 에 저장해놓고 필요시 가져오기 때문에, 지연이 발생한다.)
         *          Supplier에 저장하고 필터가 이를 필요로 하는 시점에 Supplier를 실행시켜서 세션에서 context를 꺼내옴.
         *          객체의 생성시점을 지연시킴으로서 성능상 이점을 가져갈 수 있다.
         *
         * *** SecurityContextHolder 저장 모드
         * - MODE_THREADLOCAL : 기본 모드로, 각 스레드가 독립적인 보안 컨텍스트를 가진다. 대부분의 서버 환경에 적합
         *      -> ThreadLocalSecurityContextHolderStrategy 구현체가 생성되고 SecurityContext를 저장한다.
         *
         * - MODE_INHERITABLETHREADLOCAL : 부모 스레드로부터 자식 스레드로 보안 컨텍스트가 상속되며 작업을 스레드 간 분산 실행하는 경우 유용할 수 있다.
         *    ex) 부모가 별도 스레드를 생성하면 자식에서도 표현된다.  원래는, 부모 스레드에 Security Context가 생성되면, 자식에게 상속되지 않음.
         *       부모 스레드의 Security Context 를 참조하고 싶을 때 사용하는 모드이다.
         *      -> InheritableThreadLocalSecurityContextHolderStrategy 구현체가 생성되고 SecurityContext를 저장.
         *
         * - MODE_GLOBAL : 전역적으로 단일 보안 컨텍스트를 사용하며 서버 환경에서는 부적합하며 주로 간단한 애플리케이션에 적합하다.
         *      -> GlobalSecurityContextHolderStrategy 구현체를 생성하고 SecurityContext를 저장.
         *
         *
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
