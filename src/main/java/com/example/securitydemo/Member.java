package com.example.securitydemo;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Entity
@Table(name = "members")
@Getter
@NoArgsConstructor
public class Member implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String email;  // username으로 사용할 필드

    @Column(nullable = false)
    private String password;

    private String nickname;

    @OneToMany(mappedBy = "member", cascade = CascadeType.ALL, orphanRemoval = true)
    private Set<MemberRole> roles = new HashSet<>();

    // 추가 필드 (필요 시)
    private boolean enabled = true;  // 계정 활성화 여부

    /**
     * =====================================================
     * implements UserDetails 했을 때, 반드시 구현해야 하는 것들 시작
     * =====================================================
     */
    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
                .collect(Collectors.toList());
    }
    /**
     * =====================================================
     * implements UserDetails 했을 때, 반드시 구현해야 하는 것들 끝
     * =====================================================
     */

    @Override
    public boolean isAccountNonExpired() {
        return true;  // 필요 시 로직 추가
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return enabled;  // 예: 탈퇴/정지 계정 체크
    }

    // 편의 메서드 (필요 시 추가)
    public boolean hasRole(String role) {
        return roles.contains(role);
    }
}
