package com.example.securitydemo;

import com.example.securitydemo.jwt.JwtUtils;
import com.example.securitydemo.jwt.LoginRequest;
import com.example.securitydemo.jwt.LoginResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequiredArgsConstructor
public class GreetingController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;

    @GetMapping("/hello")
    public String sayHello() {
        return "Hello";
    }

    @PreAuthorize("hasRole('USER')")
    // 스프링 시큐리티가 role 이 USER 인 놈만 이 엔드포인트 접근 가능하도록 해줌. 아닌 사람들은 403 Forbidden(인증 O, 인가 X) 임.
    @GetMapping("/user")
    public String userEndpoint() {
        return "Hello, User!";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "Hello, Admin!";
    }

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;

        try {

            // 신분증을 만들고, 유효한지 검사합니다.
            // 유효한지 검사는 어떻게 할까요? DB 에서 username 이랑 password 조회해서 일치하는지 검사합니다.
            // 유효한 경우, UserDetails 를 담고 있는 Authentication 타입 객체를 반환.
            authentication = authenticationManager
                    .authenticate(
                            /**
                             * UsernamePasswordAuthenticationToken <- 어디서 많이 보지 않았어요?
                             * AuthTokenFilter 에서 봤던 신분증 만들 때 쓰인 클래스죠?
                             * 즉, 아래 코드는 신분증을 만드는 겁니다. 이 신분증은 AuthenticationManager 로부터 인증을 받아야만 유효한 거예요.
                             */
                            new UsernamePasswordAuthenticationToken(
                                    loginRequest.getUsername(),
                                    loginRequest.getPassword()
                            )
                    );

        } catch (AuthenticationException exception) { // 유효하지 않은 경우
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<Object>(map, HttpStatus.NOT_FOUND); // 404
        }

        // 유효한 경우, 현재 이 요청을 처리하는 쓰레드에 "신분증" 을 꽂아두는 행위
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // 신분증에서 UserDetails(사용자 세부정보) 추출
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        // JWT 토큰 생성하기
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        // 권한 모으기
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken);
        return ResponseEntity.ok(response);
    }

    /**
     * 전통적인 방식
     * - 직접 SecurityContextHolder 에 저장해둔 신분증 이용하기
     * @return
     */
    @GetMapping("/profile")
    public ResponseEntity<?> getUserProfile() {
        // SecurityContextHolder 에 저장해둔 "인증토큰(신분증)" 을 가져옵니다.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 신분증에서 UserDetails(사용자 세부정보) 추출
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();

        Map<String, Object> profile = new HashMap<>();
        profile.put("username", userDetails.getUsername());
        profile.put("roles", userDetails.getAuthorities()
                .stream()
                .map(item -> item.getAuthority()).collect(Collectors.toList())
        );
        profile.put("message", "This is user-specific content form backend");
        return ResponseEntity.ok(profile);
    }

    /**
     * 요즘 방식
     * - 내부적으로는 위와 같이 SecurityContextHolder 에 저장해둔 인증토큰(신분증) 을 이용합니다.
     * - 다만, 이를 Spring MVC 의 Argument Resolver 가 대신해줍니다.
     */

}
