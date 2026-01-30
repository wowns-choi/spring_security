package com.example.securitydemo;

import com.example.securitydemo.jwt.AuthEntryPointJwt;
import com.example.securitydemo.jwt.AuthTokenFilter;
import io.jsonwebtoken.security.Password;
import org.springframework.beans.factory.annotation.Autowired;
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

//        http.authorizeHttpRequests((requests) ->
//                // /h2-console/ 로 시작하는 것들은 인증을 요구하지 않도록 함.
//                requests.requestMatchers("/h2-console/**").permitAll()
//                        // 나머지는 모두 인증을 요구하도록 함.
//                        .anyRequest().authenticated());
//
//        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
//        //        http.formLogin(withDefaults()); // <- form 기반 인증은 안하기로 했으므로.
//        http.httpBasic(withDefaults()); // 기본 인증(UI 가 없는 RESTFUL)
//        http.headers( headers ->
//                headers.frameOptions(frameOptions -> frameOptions.sameOrigin()));
//        http.csrf(csrf -> csrf.disable());
//        return http.build();

        http.authorizeHttpRequests(authorizeRequests ->
                authorizeRequests.requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/signin").permitAll()
                .anyRequest().authenticated());

        http.sessionManagement(
                session -> session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS
                )
        );

        http.exceptionHandling(exception -> exception.authenticationEntryPoint(unauthorizedHandler));

        http.headers(headers -> headers
                .frameOptions(frameOptions -> frameOptions.sameOrigin()));

        http.csrf(csrf -> csrf.disable());
        http.addFilterBefore(authenticationJwtTokenFilter(),
                UsernamePasswordAuthenticationFilter.class);
        return http.build();

    }

//    @Bean
//    public UserDetailsService userDetailsService(){
//
//        UserDetails user1 = User.withUsername("user1")
//                .password("{noop}password1")
//                .roles("USER")
//                .build();
//
//        UserDetails admin = User.withUsername("admin")
//                .password("{noop}adminPass")
//                .roles("ADMIN")
//                .build();
//
//        return new InMemoryUserDetailsManager(user1, admin);
//    }

    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user1 = User.withUsername("user1")
//                .password("{noop}password1")
                .password(passwordEncoder().encode("password1"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
//                .password("{noop}adminPass")
                .password(passwordEncoder().encode("adminPass"))
                .roles("ADMIN")
                .build();


        // JdbcUserDetailsManager 생성자 중에는 아래처럼 DataSource 타입 객체를 매개변수로 받는 생성자가 있음
        /**
         * 1. InMemoryUserDetailsManager 처럼, UserDetailsManager 를 implement 하고 있으며, UserDetailsManager 는 UserDetailsService 를 extends 하고 있음.
         *
         * 2. JdbcUserDetailsManager 생성자 중에는 아래처럼 DataSource 타입 객체를 매개변수로 받는 생성자가 있음
         * public JdbcUserDetailsManager(DataSource dataSource) {
         * 		setDataSource(dataSource);
         * 	    }
         *
         * 3. 스프링 부트는 application.properties 에 써둔 데이터베이스 접근 정보와 도입한 라이브러리를 보고 알아서 DataSource 타입 빈을 만들어서 스프링 컨테이너에 둡니다.
         * 위에서 주입해둔 거 쓰겠습니다.
         */

        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);
        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
        return userDetailsManager;

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
