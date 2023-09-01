package my.tony.securityjwt.member.controller;

import lombok.RequiredArgsConstructor;
import my.tony.securityjwt.member.dto.MemberRequest;
import my.tony.securityjwt.member.dto.MemberResponse;
import my.tony.securityjwt.member.repository.MemberRepository;
import my.tony.securityjwt.member.service.MemberService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
public class MemberController {

    private final MemberRepository memberRepository;
    private final MemberService memberService;

    @PostMapping("/login")
    public ResponseEntity<MemberResponse> signIn(@RequestBody MemberRequest request) throws Exception {
        return new ResponseEntity<>(memberService.login(request), HttpStatus.OK);
    }

    @PostMapping("/register")
    public ResponseEntity<Boolean> signUp(@RequestBody MemberRequest request) throws Exception {
        return new ResponseEntity<>(memberService.regiter(request), HttpStatus.OK);
    }

    @GetMapping("/user/get")
    public ResponseEntity<MemberResponse> getUser(@RequestParam String account) throws Exception {
        return new ResponseEntity<>(memberService.getMember(account), HttpStatus.OK);
    }

    @GetMapping("/admin/get")
    public ResponseEntity<MemberResponse> getUserForAdmin(@RequestParam String account) throws Exception {
        return new ResponseEntity<>( memberService.getMember(account), HttpStatus.OK);
    }
}
