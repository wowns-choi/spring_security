
/**
 * 1. CORS 정책 :
 *   현재 페이지를 보기 위해서 한 HTTP 콜의 오리진 과
 *   fetch, axios 등으로 HTTP 콜 하려는 서버의 오리진이
 *   다르다면 => Cross Origin Resource Sharing(교차되는(서로다른) 출처의 리소스는 공유하지 마라)정책 위반입니다.
 *   Origin 은 "출처" 라고도 표현하는데요. 여기서의 Origin 은 프로토콜(http://), 도메인(www.naver.com), 포트번호(:8080) 모두를 의미하므로, 셋 중에 하나라도 다르면 CORS 위반 입니다.
 *
 *   2. 브라우저의 동작방식  :
 *   - http://siteA.com:8080 을 호출함으로써 HTML 을 얻은 사용자가 해당 HTML 의 버튼을 클릭해서 http://siteB.com:8080 에 회원가입 정보를 보낸다고 해봅시다.
 *   - 그러면, 브라우저는 "잠깐만. CORS 정책 위반이네. http://siteB.com:8080 한테 허용할건지 물어볼게" 하고 OPTIONS(프리플라이트) 요청을 먼저 보냅니다.
 *   - http://siteB.com:8080 는 응답 헤더에 다음 두가지를 붙여서 "http://siteA.com:8080 에서 GET,POST 요청 보내도 괜찮아~" 라고 알려줍니다.
 *    * Access-Control-Allow-Origin: https://siteA.com:8080
 *    * Access-Control-Allow-Methods: GET,POST
 *   - 브라우저는 "허락 받았으니, 실제 GET/POST 요청을 http://siteB.com:8080 에게 보내야겠다" 하고 데이터를 요청합니다.
 *   - 문서 오리진 : 지금 이 페이지(브라우저)가 어느 오리진에서 로드됐는가 => http://siteA.com:8080 을 가리킴
 *   - 요청 대상 오리진 : 이 HTTP 요청이 어느 오리진으로 향하는가 => http:siteB.com
 *
 *  3. "2. 브라우저의 동작방식" 에서 설명한 것은 siteA.com -> siteB.com 에 보내려는 HTTP 메세지의 메소드가 PUT, DELETE, PATCH 인 경우에만 해당, GET, POST 는 특정조건 만족할 경우 프리플라이트 보내는 과정 없음
 */

/**
 * Spring Security 를 도입하면, 이 라이브러리가 위치하는 곳이 "필터" 부분이죠?
 * 근데, 아래 있는 WebMvcConfigurer 는 디스패처 서블릿을 거친 이후에 실행되거든요?
 * 즉, Spring Security Filter Chain -> Dispatcher Servlet -> WebMvcConfigurer
 *
 * 따라서, Spring Security 를 도입하면서 Cors 설정을 아래처럼 WebMvcConfigurer 를 사용한다면,
 * 브라우저가 OPTIONS(프리플라이트) 요청을 보내왔을 때, Spring Security 가 먼저 이를 받기 때문에,
 * "너 누구임? 인증 안됬네? 401응답이다 이녀석아" 하게 됨. 그래서, WebMvcConfigurer 까지 도달조차 못함.
 *
 * 따라서, 깔끔하게 Spring Security 를 통해서 CORS 설정을 하면 됨.
 * Spring Security 를 통해서 CORS 설정을 하면, Spring Security Filter Chain 가장 앞단에 CORS 검사를 하는 필터를 두게 됩니다.
 * 그러면, 브라우저가 보낸 OPTIONS 요청이 들어오면, "얘가 로그인을 했나?"를 검사하기 전에 "CORS 설정에 등록된 오리진인가?" 를 먼저 확인합니다
 * 허용된 오리진 이라면 즉시 200 OK와 함께 CORS 헤더를 붙여 응답합니다
 */

//package com.example.securitydemo.jwt;
//
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.web.servlet.config.annotation.CorsRegistry;
//import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
//
//@Configuration
//public class WebConfig implements WebMvcConfigurer {
//
//    @Bean
//    public WebMvcConfigurer corsConfigurer() {
//        return new WebMvcConfigurer() {
//            @Override
//            public void addCorsMappings(CorsRegistry registry) {
//                registry
//                        .addMapping("/**") // 애플리케이션의 모든 엔드포인트에 이 CORS 규칙을 적용
//                        // allowedOrigins : 허용할 문서 오리진의 도메인을 써주시면 됩니다.
//                        // - 개발환경 : http://localhost:3000 이 됩니다.
//                        // - 배포환경 : 리소스를 서빙하고 있는 Nginx 서버(프론트서버) 의 오리진을 써주시면 됩니다. 쉽게 말해, AWS 서버의 오리진을 써주시라는 의미입니다.
//                        // 배포환경에서, 사용자 컴퓨터가 속해있는 공인IP:포트번호 써줘야 하는거 아니예요?
//                        // 아닙니다. 스프링 서버에 HTTP콜을 하는 사용자 브라우저의 오리진은 "문서 오리진" 입니다.
//                        .allowedOrigins("http://localhost:3000")
//                        .allowedMethods("GET", "POST", "PUT", "DELETE",  "OPTIONS") // 모든 HTTP 요청 메서드에 대해 허용
//                        .allowedHeaders("*") // 모든 헤더 허용
//                        .allowCredentials(true) // HTTP콜을 받을 때, 내가(요청 대상 오리진이) 발급한 쿠키를 받겠다.
//                        .maxAge(3600); // 3600초(1시간) 동안 브라우저가 프리플라이트 응답을 캐싱
//            }
//        };
//    }
//}
