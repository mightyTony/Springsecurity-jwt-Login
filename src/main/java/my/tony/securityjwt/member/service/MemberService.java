package my.tony.securityjwt.member.service;

import lombok.RequiredArgsConstructor;
import my.tony.securityjwt.member.dto.MemberRequest;
import my.tony.securityjwt.member.dto.MemberResponse;
import my.tony.securityjwt.member.entity.Authority;
import my.tony.securityjwt.member.entity.Member;
import my.tony.securityjwt.member.repository.MemberRepository;
import my.tony.securityjwt.config.security.JwtProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
//@Transactional
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtProvider jwtProvider;

    /**
     * 로그인
     */
    public MemberResponse login(MemberRequest request) throws Exception {
        Member member = memberRepository.findByAccount(request.getAccount())
                .orElseThrow(() -> new BadCredentialsException("잘못된 계정 정보 입니다."));

        if (!passwordEncoder.matches(request.getPassword(), member.getPassword())) {
            throw new BadCredentialsException("잘못된 계정 정보 입니다.");
        }

        // String token = jwtProvider.createToken(member.getAccount(), member.getRoles())
        // token 헤더에 넣는 작업 후 builder에 넣자
        return MemberResponse.builder()
                .id(member.getId())
                .account(member.getAccount())
                .name(member.getName())
                .email(member.getEmail())
                .nickname(member.getNickname())
                .roles(member.getRoles())
                //.token(jwtProvider.createToken(member.getAccount(), member.getRoles()))
                .token(jwtProvider.createToken(member.getAccount(), member.getRoles()))
                .build();
    }

    // 회원가입
    public boolean regiter(MemberRequest request) throws Exception {

        // 유저가 입력한 암호 bcrypt 암호화 해서 저장
        String encodedPassword = passwordEncoder.encode(request.getPassword());

        try {
            Member member = Member.builder()
                    .account(request.getAccount())
                    .password(encodedPassword)
                    .name(request.getName())
                    .nickname(request.getNickname())
                    .email(request.getEmail())
                    .build();
            member.setRoles(Collections.singletonList(Authority.builder().name("ROLE_USER").build()));

            memberRepository.save(member);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            throw new Exception("잘못된 요청입니다");
        }
        return true;
    }

    // 회원 조회
    public MemberResponse getMember(String account) throws Exception {
        Member member = memberRepository.findByAccount(account)
                .orElseThrow(() -> new UsernameNotFoundException("유저를 찾을 수 없습니다."));
        return new MemberResponse(member);
    }
}
