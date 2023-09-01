package my.tony.securityjwt.member.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class MemberRequest {

    @JsonIgnore
    private Long id;

    private String account;

    private String password;

    private String nickname;

    private String name;

    private String email;
}
