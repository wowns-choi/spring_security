package com.example.securitydemo;

import com.example.securitydemo.jwt.AuthEntryPointJwt;
import com.example.securitydemo.jwt.AuthTokenFilter;
import io.jsonwebtoken.security.Password;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * 사용자 지정 보안 설정하기
 */
// 스프링부트야. 이건 설정 클래스야.
@Configuration
// "스프링부트, 나 @EnableWebSecurity 눌러서 보안 스위치 켰어.
// 그러니까, 내가 @Bean으로 등록한 SecurityFilterChain(내 보안 설정객체)을 찾아서, 그대로 실행해 줘."
// 라는 의미입니다. 그래서 스프링 부트는 이 애노테이션을 보고 밑에 등록한 SecurityFilterChain 타입 빈을 찾아서 실행해주게 되는 것입니다.
// 즉, @EnableWebSecurity 는 커스텀한 보안 설정객체를 만든 다음에 켜는 스위치 라고 비유할 수 있습니다.
@EnableWebSecurity
// @PreAuthorize 가 동작하려면, @EnableMethodSecurity 가 필요함.
@EnableMethodSecurity
public class SecurityConfig {

    @Autowired
    DataSource dataSource;

    @Autowired
    private AuthEntryPointJwt unauthorizedHandler;

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter() {
        return new AuthTokenFilter();
    }


    // SecurityFilterChain 타입 빈 : 보안 설정 객체
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests
                        // /h2-console/ 로 시작하는 것들은 인증을 요구하지 않도록 함.
                        .requestMatchers("/h2-console/**").permitAll()
                        // /signin 로 시작하는 것들은 인증을 요구하지 않도록 함.
                        .requestMatchers("/signin").permitAll()
                        // 나머지는 모두 인증 요구
                        .anyRequest().authenticated());

        // 세션 안쓰기
        http.sessionManagement(
                session -> session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS
                )
        );

        // 인증과 관련된 오류(비밀번호 틀리다거나, 아이디가 없다거나..)가 발생했을 경우 스프링 시큐리티 라이브러리는 예외를 터뜨립니다.
        // 그러한 예외들의 최상위 부모가 AuthenticationException 입니다.
        // 그 예외를 잡아서 우리가 만들었던 AuthEntryPointJwt 로 진입시킵니다. 즉, AuthEntryPointJwt 는 예외를 처리하는 진입점이 되는 것입니다.
        // 그럼 인가와 관련된 오류가 났을 경우에는요? 그럴 경우에도 아래 코드로 인해 AuthEntryPointJwt 로 진입할까요? 아닙니다.
        // 인가와 관련된 예외는 AccessDeniedException 가 최상위 예외이며, AuthenticationException 와는 독립됩니다. 이 경우, 403 응답이 나가게 된다고 합니다.
        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));

        // 이건 h2 console 오류 해결을 위함이었음.
        http.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.sameOrigin()));

        // 이건 h2 console 오류 해결을 위함이었음.
        http.csrf(csrf -> csrf.disable());

        /**
         * ================================================
         * 폼 로그인(http.formLogin(withDefaults());) 도 아니고,
         * 기본인증(http.httpBasic(withDefaults());) 도 아님.
         * ================================================
         */

        // addFilterBefore(A, B) : A 실행한 후에 B 실행해라.
        http.addFilterBefore(
                // AuthTokenFilter 빈이 주입됨.
                authenticationJwtTokenFilter(),
                // AuthTokenFilter 는 SecurityContextHolder 에 신분증을 꽂아두죠?  UsernamePasswordAuthenticationFilter 는 SecurityContextHolder 에 신분증 꽂혀있으면 바로 다음 필터로 넘어갑니다.
                // 참고로, UsernamePasswordAuthenticationFilter 는 Spring Security가 기본적으로 제공하는 필터로, 아이디와 비밀번호를 이용한 폼 로그인을 처리합니다.
                UsernamePasswordAuthenticationFilter.class
        );

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(){
        // UserDetailsService : 인터페이스(1)
        // UserDetailsManager : 인터페이스(2)
        // JdbcUserDetailsManager : 클래스(3)

        // 2는 1을 상속하고, 3은 2를 구현하고 있습니다.
        // UserDetailsService(1) 의 역할은 2개로 나눌 수 있음.
        // - 사용자 이름을 받아서 데이터베이스 등에서 사용자 정보를 조회해서 그 정보로 UserDetails 타입 객체를 만들어서 반환함.
        // - UserDetails 타입 객체를 받아 DB 저장
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource); // 스프링 부트는 application.properties 에 써둔 데이터베이스 접근 정보와 도입한 라이브러리를 보고 알아서 DataSource 타입 빈을 만들어서 스프링 컨테이너에 둡니다.
        return userDetailsManager;

    }

    /**
     * CommandLineRunner : 애플리케이션이 완전히 구동된 후에 특정한 작업을 하고 싶을 때 사용합니다.
     * 그래서 지금 왜 쓰냐? 원래는 위 메서드(userDetailsService) 에서 곧바로 user1 과 admin 을 생성하고 DB 에 넣었었음. 근데, 빈 생성이 테이블 생성(schema.sql)보다 빨라서 "그런 테이블 없는데?" 라는 에러가 남.
     * 그래서, 애플리케이션이 완전히 구동된 후(schema.sql 까지 실행된 후) 행 2개 넣으라고 하기 위해 쓰는겁니다.
     * @param userDetailsManager : 바로 위에서 만든 빈이 주입됩니다.
     * @param passwordEncoder
     * @return
     */
    @Bean
    public CommandLineRunner initData(JdbcUserDetailsManager userDetailsManager, PasswordEncoder passwordEncoder) {
        return args -> {

            // user1 생성
            UserDetails user1 = User.withUsername("user1")
                    .password(passwordEncoder.encode("password1"))
                    .roles("USER")
                    .build();
            userDetailsManager.createUser(user1);

            // admin 생성
            UserDetails admin = User.withUsername("admin")
                    .password(passwordEncoder.encode("adminPass"))
                    .roles("ADMIN")
                    .build();
            userDetailsManager.createUser(admin);

        };
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder)
            throws Exception {
        return builder.getAuthenticationManager();
    }

}
