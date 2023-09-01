package my.tony.securityjwt.config.security;

import lombok.RequiredArgsConstructor;
import my.tony.securityjwt.member.entity.Member;
import my.tony.securityjwt.member.repository.MemberRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * UserDetails(CustomUserDetails) 에서 받은 정보를 토대로 유저 정보를 불러 올 때 사용 된다.
 */
@Service
@RequiredArgsConstructor
public class JpaUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    // 사용자 이름(아이디)를 기반으로 사용자 정보를 가져오는 역할, 사용자 인증 과정에서 사용
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Member member = memberRepository.findByAccount(username)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid authentication, 잘못된 인증입니다."));

        return new CustomUserDetails(member);
    }
}
