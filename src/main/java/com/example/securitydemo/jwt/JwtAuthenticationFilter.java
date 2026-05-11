package com.example.securitydemo.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


/**
 * OncePerRequestFilter : "요청 당 한번" 필터 => HTTP 요청 당 딱 한번만 실행되는 필터였으면 할 때 사용.
 * 원래 필터는 한번만 실행되지 않음?
 * - /dashboard 엔드포인트에 접근했는데, 로그인 안되있어서 /login 으로 Forward 하는 경우 필터를 한 번 더 거칠수 있음.
 * - 비동기 요청인 경우, 스레드 1 이 필터를 통과한 후, 비동기 작업을 마치고 나서 서블릿컨테이너로 돌아와서 스레드 2를 할당받으면 스레드2가 다시 필터를 통과할 수 있음.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    /**
     * 이거 어디서 만들었죠? SecurityConfig 에서 저희가 직접 만들어준 빈입니다.
     * 구현체로 JdbcUserDetailsManager 를 썻었죠?
     * 여기서는 username 을 받아 사용자 정보를 조회해서 UserDetails 타입 객체를 만드는데 사용하고 있습니다.
     */
    @Autowired
    private UserDetailsService userDetailsService;

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        logger.debug("AuthTokenFilter called for URI: {}", request.getRequestURI());

        try {
            // HTTP 요청 메세지에서 JWT 토큰 가져오기
            String jwt = parseJwt(request);

            if (jwt != null && jwtUtils.validateJwtToken(jwt)) { /// 유효하다면 ~

                // 이름 추출
                String username = jwtUtils.getUserNameFromJwtToken(jwt);

                /**
                 * 여기!! ==
                 * UserDetailService 의 역할인 DB 에서 사용자 정보 조회를 하고 있는 모습입니다.
                 * 스프링 시큐리티를 쓸 때, 테이블의 구조는 정해져 있을까요?
                 * 지금까지 우리는 https://github.com/spring-projects/spring-security 에서 테이블 구조를 얻어와서 schema.sql 에 뒀었죠?
                 * user 라는 이름 말고, Member 라는 이름으로 하면 안될까요?
                 *
                 * 됩니다. 그러기 위해서는 DB에서 사용자 정보를 조회해오는 UserDetailService 를 커스터마이징 할 필요가 있습니다.
                 * CustomUserDetailsService 이라고 만들어뒀으니, 참고해주세요.
                 *
                 */
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//                Member member = (Member) userDetailsService.loadUserByUsername(username);

                // 여기까지 왔다면, JWT 토큰이 유효하면서 && 실제로 DB 에 존재하는 사용자겠죠?
                // 이 사용자에 대한 "인증토큰(신분증)" 을 만듭니다. 앞으로 신분증이라고 표현하겠습니다.
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userDetails, // <- 이게 principal 입니다. 개중요!
                        null,
                        userDetails.getAuthorities()
                );

                logger.debug("Roles from JWT: {}", userDetails.getAuthorities());
                authentication.setDetails(new WebAuthenticationDetailsSource()); // 신분증 뒷면에 사용자의 IP 주소등을 써넣는 역할을 합니다.

                // 현재 이 요청을 처리하는 쓰레드에 "신분증" 을 꽂아두는 행위
                SecurityContextHolder.getContext().setAuthentication(authentication);
            }

        } catch (Exception e) {
            logger.error("Cannot set user authentication: {}", e);
        }

        // "다음 필터로 넘어가라" 는 뜻
        filterChain.doFilter(request, response);
    }

    /**
     * JWT 토큰 추출
     * @param request
     * @return 파싱된 JWT 토큰
     */
    private String parseJwt(HttpServletRequest request) {
        String jwt = jwtUtils.getJwtFromHeader(request);
        logger.debug("AuthTokenFilter.java: {}", jwt);
        return jwt;
    }
}
