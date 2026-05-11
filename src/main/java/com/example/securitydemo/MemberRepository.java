package com.example.securitydemo;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {

    // 패치 조인. 권한까지 가져오기.
    @Query("select m from Member m join fetch m.roles where m.email = :email")
    Optional<Member> findByEmailWithRoles(@Param("email") String email);
}
