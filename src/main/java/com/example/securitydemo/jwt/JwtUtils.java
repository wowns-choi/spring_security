package com.example.securitydemo.jwt;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Date;

/**
 * 대칭키 방식 JWT
 * - JWT 생성할 때 : 비밀키(SecretKey) 사용
 * - JWT 유효성 검사할 때 : 비밀키(SecretKey) 사용
 */
@Component
public class JwtUtils {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    // 비밀키
    @Value("${spring.app.jwtSecret}")
    private String jwtSecret;

    @Value("${spring.app.jwtExpirationMs}")
    private int jwtExpirationMs;

    /**
     * HTTP 요청 헤더에서 JWT 토큰 추출하는 메서드
     */
    public String getJwtFromHeader(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization Header: {}", bearerToken);
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7); // "Bearer " 라는 prefix(접두사) 제거
        }
        return null;
    }

    /**
     * Username 으로 JWT 토큰 만들기
     * @param userDetails : 사용자 세부 정보
     */
    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date (( new Date()) .getTime() + jwtExpirationMs))
                .signWith(key())
                .compact();
    }

    /**
     *
     * BASE64 인코딩 : 바이트배열(10101110..) -> 문자(SGVsbG8=) 로 변환
     * BASE64 디코딩 :                     <-               로 변환
     *
     * Decoders.BASE64.decode(문자열) : BASE64 디코딩을 하겠다는 뜻.
     *
     * Keys.hmacShaKeyFor(바이트배열) : 바이트배열을 이용해서 대칭키를 만듦.
     */
    private Key key() {
        return Keys.hmacShaKeyFor(
                Decoders
                        .BASE64
                        .decode(jwtSecret)
        );
    }

    /**
     * =================================================
     * JWT 토큰에서 Subject(Username) 추출하기
     * =================================================
     * 1. Jwts.parse() : 파서(해체기계) 만들기
     *
     * 2. verifyWith(비밀키)
     *   - 지금 만들 파서는 이 비밀키로 JWT 토큰의 유효성 검증을 진행한다.
     *   - 아래 보면, (SecretKey) 라고 되어 있는데, 이건 뭘까?
     *     - jjwt 라이브러리 최신 버전 0.12.0 이상부터는
     *       => 대칭키인 경우 SecretKey 타입 객체를 요구하고,
     *       => 비대칭키인 경우 PublicKey 타입 객체를 요구합니다.
     *     - 이 파일에서는 대칭키를 다루므로, SecretKey 타입 객체가 필요해서 형 변환 해준겁니다.
     *
     * 3. build() : 파서 만들기 끝
     *
     * 4. parseSignedClaims(JWT토큰) : 파서로 JWT 토큰 유효성 검사. 이때, 유효하지 않은 JWT 토큰이거나 그러면 예외 터질 수 있음.
     *
     * 5. getPayload() : JWT 토큰의 구성요소(헤더, 페이로드, 서명) 중 페이로드 추출
     *
     * 6. getSubject() : payload 에 들어있는 claim 들 중 subject 꺼내오기
     */
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith((SecretKey) key())
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    /**
     * JWT 토큰 검증
     */
    public boolean validateJwtToken(String authToken) {
        try {
            System.out.println("Validate");
            Jwts.parser()
                    .verifyWith((SecretKey) key())
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token : {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }




}
