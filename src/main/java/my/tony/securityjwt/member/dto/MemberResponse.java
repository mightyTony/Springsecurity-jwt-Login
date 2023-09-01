package my.tony.securityjwt.member.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import my.tony.securityjwt.member.entity.Authority;
import my.tony.securityjwt.member.entity.Member;

import java.util.ArrayList;
import java.util.List;

@Getter @Builder @AllArgsConstructor @NoArgsConstructor
public class MemberResponse {

    private Long id;

    private String account;

    private String nickname;

    private String name;

    private String email;

    private List<Authority> roles = new ArrayList<>();

    private String token;

    public MemberResponse(Member member) {
        this.id = member.getId();
        this.account = member.getAccount();
        this.nickname = member.getNickname();
        this.name = member.getName();
        this.email = member.getEmail();
        this.roles = member.getRoles();
    }
}
