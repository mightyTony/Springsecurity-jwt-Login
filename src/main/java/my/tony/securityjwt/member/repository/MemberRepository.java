package my.tony.securityjwt.member.repository;

import my.tony.securityjwt.member.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Transactional
public interface MemberRepository extends JpaRepository<Member, Long> {

    Optional<Member> findByAccount(String account);
}
