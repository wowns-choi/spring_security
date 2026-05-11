package com.example.securitydemo.jwt;

/**
 * 커스터마이징한 UserDetailsService
 * 실제로 동작하게 하려면?
 * 1. SecurityConfig.java 에서 UserDetailsService 타입 빈 등록하는 거 주석처리해야함. 아래에 @Service 로 인해 이 클래스로 만든 빈이 스프링 컨테이너에 빈으로 관리되게 되었음.
 * 2. AuthTokenFilter.java 에서 사용자 정보 조회 후 Member 로 형변환해서 신분증 principal 에 넣을 때 Member 로 넣어주면 됨.
 *
 * 이런 의문이 들 수 있음.
 * CustomUserDetailsService 가 UserDetailsService 를 implements 하지 않으면 되는 거 아님? 그럼 Member 가 UserDetails 를 implements 할 필요도 없어지잖아.
 * 그런 다음에 신분증에 principal 에다가 그냥 Member 넣으면 되잖아?
 *
 * 결론 : 그러지 마세요.
 * signin 할 때, AuthenticationManager 를 이용해서 authenticate() 하죠?
 * 이때, AuthenticationProvider 라는 게 내부적으로 UserDetailService 를 이용해서 DB 에서 사용자 정보를 조회한단 말이예요.
 * 근데 스프링이 UserDetailService 를 implements 한 빈이 있나 찾아봤는데 없을거 아니예요? 그래서 에러남.
 *
 * 또한, @PreAuthorize("hasRole('ADMIN')") 이런것도 잘 안되게 됨.
 *
 *
 */

//@Service
//@RequiredArgsConstructor
//public class CustomUserDetailsService implements UserDetailsService { /// UserDetailsService 를 implements 하면, loadUserByUsername 을 오버라이딩 해야함.
//
//    private final MemberRepository memberRepository; // 있다고 가정하겠음.
//
//    @Override
//    /// 반드시 UserDetails 타입 객체를 반환해야함. 따라서, Member 가 UserDetails 를 implements 하도록 함.
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//
//        Member member = memberRepository.findByEmailWithRoles(username)
//                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));
//
//        return member;  // Member 가 UserDetails 를 implements 했으므로, 그대로 반환 가능.
//    }
//
//}
