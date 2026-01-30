package com.example.securitydemo.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

/**
 * 들어가기전 한마디 : 대칭키 방식부터 보고 오세요.
 * 비대칭키 방식 JWT
 * - JWT 생성할 때 : 개인키(PrivateKey) 사용
 * - JWT 유효성 검사할 때 : 공개키(PublicKey) 사용
 */
@Component
public class AsymmetricJwtUtils {
    private static final Logger logger = LoggerFactory.getLogger(AsymmetricJwtUtils.class);

    /**
     * 개인키 만드는 법 : openssl genrsa -out private.pem 2048
     * - openssl : 윈도우, 맥, 리눅스 기본 내장 라이브러리
     * - genrsa : "generate rsa" rsa 알고리즘을 이용해서 2048 비트 길이의 키를 만들어서 줘라. 즉, 키 깍아서 줘라는 의미임.
     * - out private.pem : private.pem 이라는 파일로 저장해라
     * - 2048 : 키의 비트수
     *
     * openssl 아, rsa 라는 알고리즘을 사용해서 2048비트 길이의 키(열쇠, 어떤 데이터를 보호할 수 있는 열쇠)를 만들어줘.
     * 그리고, 2048비트 길이의 키는 Base64 로 인코딩되어 문자로 변환됨.
     * 그게 private.pem 파일에 적혀진 것입니다.
     */
    @Value("${spring.app.jwtPrivateKey}")
    private String jwtPrivateKey;

    /**
     * 공개키 만드는 법 : openssl rsa -in private.pem -pubout -out public.pem
     * - openssl rsa : openssl 아, rsa 알고리즘 관련 작업을 할거야.
     * - -in private.pem : 입력(input)으로 private.pem 파일을 사용할게.
     * - -pubout -out public.pem : public key 를 추출해서 public.pem 파일을 만들어줘.
     *
     * 무슨 소리냐면, private.pem 안에는 public key 를 만들 때 사용할 재료가 들어있으니,
     * 거기서 public key 를 추출해서 public.pem 파일을 만들어달라는 겁니다.
     */
    @Value("${spring.app.jwtPublicKey}")
    private String jwtPublicKey;

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
     * PrivateKey(개인키) 로 서명!
     */
    public String generateTokenFromUsername(UserDetails userDetails) {
        String username = userDetails.getUsername();
        return Jwts.builder()
                .subject(username)
                .issuedAt(new Date())
                .expiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(getPrivateKey()) // 개인키로 서명
                .compact();
    }

    /**
     * =================================================
     * JWT 토큰에서 Subject(Username) 추출하기
     * PublicKey(공개키) 로 유효성 검사
     * =================================================
     */
    public String getUserNameFromJwtToken(String token) {
        return Jwts.parser()
                .verifyWith(getPublicKey()) // 공개키로 검증
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    /**
     * JWT 토큰 검증
     * PublicKey(공개키) 로 유효성 검사
     */
    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parser()
                    .verifyWith(getPublicKey()) // 공개키로 검증
                    .build()
                    .parseSignedClaims(authToken);
            return true;
        } catch (MalformedJwtException | ExpiredJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            logger.error("JWT validation error: {}", e.getMessage());
        }
        return false;
    }


    /**
     * BASE64 문자열로 된 개인키를 -> 자바 PrivateKey 객체로 변환
     */
    private PrivateKey getPrivateKey() {
        try {
            // Base64 로 인코딩된 결과물인 "문자열"을 -> 바이트 배열로 디코딩
            byte[] keyBytes = Decoders.BASE64.decode(jwtPrivateKey);

            // 아래에서 키 공장(키를 생산해내는 공장)을 통해서 PrivateKey 타입 객체를 만들어낼 예정인데요.
            // 이때, 바이트배열을 매개변수로 넘겨주면, 키 공장은 이 바이트 배열이 뭔지 모릅니다.
            // 따라서, PKCS8EncodedKeySpec 타입 객체로 감싸서 이 바이트 배열이 PKCS#8 규칙에 따라 읽으면 되는 키 만들 때 필요한 재료 라는 것을 알려주는 겁니다.
            // EncodedKeySpec 은 이 바이트 배열이 키 만들 때 사용되는 재료임을 나타내며,
            // PKCS8 은 이 바이트 배열을 읽을 때의 규칙을 나타냅니다.
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

            // RSA 알고리즘을 이용해서 키를 생산해내는 키 공장을 만듦.
            KeyFactory kf = KeyFactory.getInstance("RSA");

            // 키 공장을 이용해서 PrivateKey 타입 객체 생성
            return kf.generatePrivate(spec);

        } catch (Exception e) {
            throw new RuntimeException("개인키 생성 실패", e);
        }
    }

    /**
     * BASE64 문자열로 된 공개키를 -> 자바 PublicKey 객체로 변환
     */
    private PublicKey getPublicKey() {
        try {
            // Base64 로 인코딩된 결과물인 "문자열"을 -> 바이트 배열로 디코딩
            byte[] keyBytes = Decoders.BASE64.decode(jwtPublicKey);

            // 아래에서 키 공장(키를 생산해내는 공장)을 통해서 PublicKey 타입 객체를 만들어낼 예정인데요.
            // 이때, 바이트배열을 매개변수로 넘겨주면, 키 공장은 이 바이트 배열이 뭔지 모릅니다.
            // 따라서, X509EncodedKeySpec 타입 객체로 감싸서 이 바이트 배열이 X509 규칙에 따라 읽으면 되는 키 만들 때 필요한 재료 라는 것을 알려주는 겁니다.
            // EncodedKeySpec 은 이 바이트 배열이 키 만들 때 사용되는 재료임을 나타내며,
            // X509 은 이 바이트 배열을 읽을 때의 규칙을 나타냅니다.
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);

            // RSA 알고리즘을 이용해서 키를 생산해내는 키 공장을 만듦.
            KeyFactory kf = KeyFactory.getInstance("RSA");

            // 키 공장을 이용해서 PublicKey 타입 객체 생성
            return kf.generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("공개키 생성 실패", e);
        }
    }
}
