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
import org.springframework.security.core.annotation.AuthenticationPrincipal;
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
/**
 * == 메서드 레벨 인가 ==
 *
 * ## 들어가기 전에, SecurityConfig.java 에 @EnableMethodSecurity 잊지 마세요.
 *
 * @PreAuthorize(SpEL) : 메서드 실행 전 권한 체크
 * - 클래스레벨에 쓸 수도 있음.
 * - 서비스계층에도 쓸 수 있음.
 * - 예시 - 1) @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
 * - 예시 - 2) @PreAuthorize("#document.owner == authentication.name")
 *
 * @PostAuthorize(SpEL) : 메서드 실행 후 권한 체크.
 *
 * @PreFilter(SpEL) : 메서드 실행 전 권한 체크.
 * - 메서드가 컬렉션(리스트, 배열, 맵, 스트림 등) 을 받을 때, 그 컬렉션 안 각 요소들을 대상으로 어떠한 작업을 하고 싶다면, 이걸 쓰세요.
 * - 컬렉션 안 각 요소들을 filterObject 라고 지칭함.
 *
 * @PostFilter((SpEL)) : 메서드가 실행된 후 반환되는 컬렉션(리스트, 배열, 맵 등)을 자동으로 필터링하는 역할
 *
 */
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
        // AuthTokenFilter 에서 SecurityContextHolder 에 인증토큰(신분증)인 UsernamePasswordAuthenticationToken 담아뒀었잖아요.
        // UsernamePasswordAuthenticationToken 은 Authentication 이라는 인터페이스를 구현합니다.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        // 신분증에서 UserDetails(사용자 세부정보) 추출
        // principal 로 뭘 설정해 두었는가? 에 따라서, 다른 타입의 객체가 올 수 있습니다.
        // AuthTokenFilter 에서 UsernamePasswordAuthenticationToken 을 만들때, 생성자의 첫번째 자리가 principal 이거든요.
        // 여기에 UserDetails 타입 객체를 줬기 때문에 지금 UserDetails 타입 객체를 얻을 수 있는겁니다.
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
     * - Spring MVC 의 Argument Resolver 가 내부적으로 다음과 같은 행위를 해줍니다.
     * - SecurityContextHolder 에 저장해둔 인증토큰(신분증) 을 꺼내서, 그 안에 들어있는 principal 을 꺼내서 아래 컨트롤러에 바인딩해주는 겁니다.
     *
     * 따라서, 만약에 SecurityContextHolder 의 principal 에 Member 를 저장해뒀다면? 여기서 Member 로 받을 수 있는겁니다.
     */
    @GetMapping("/profile2")
    public ResponseEntity<?> getUserProfile2(@AuthenticationPrincipal UserDetails userDetails) {

        Map<String, Object> profile = new HashMap<>();
        profile.put("username", userDetails.getUsername());
        profile.put("roles", userDetails.getAuthorities()
                .stream()
                .map(item -> item.getAuthority()).collect(Collectors.toList())
        );
        profile.put("message", "This is user-specific content form backend");
        return ResponseEntity.ok(profile);
    }

}
