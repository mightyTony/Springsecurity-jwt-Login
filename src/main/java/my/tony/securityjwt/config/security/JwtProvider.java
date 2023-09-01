package my.tony.securityjwt.config.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import my.tony.securityjwt.member.entity.Authority;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    @Value("${jwt.secret.key}")
    private String salt;

    private Key secretKey;

    private final Long expirationTime = 1000L * 60 * 60; // 만료시간 1시간

    private final JpaUserDetailsService userDetailsService;

    @PostConstruct // 빈 주입 된 후 실행 될 때 마다 초기화 작업
    protected void init() {
        // HMAC-SHA 해시 알고리즘을 이용해 시크릿 키 생성
        secretKey = Keys.hmacShaKeyFor(salt.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * 토큰 생성
     */
    // Claim 이라는 사용자에 대한 프로퍼티나 속성을 이야기 합니다. 토큰 자체가 정보를 가지고 있는 방식인데, JWT는 이 Claim을 JSON을 이용해서 정의 합니다.
    public String createToken(String account, List<Authority> roles) {
        Claims claims = Jwts.claims().setSubject(account);
        claims.put("roles", roles);
        Date now = new Date();

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expirationTime))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    // 권한 정보 획득, Security 인증 과정에서 권한 확인을 위한 기능
    public Authentication getAuthentication(String token) {
        UserDetails userDetails =userDetailsService.loadUserByUsername(getAccount(token));

        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    // JWT(토큰)에 담겨져 있는 사용자 계정(subject) 추출 메서드
    private String getAccount(String token) {
        /**
         * Jwts.parserBuilder() : JWT 파싱 객체
         * .setSigningKey(secretKey) : JWT 검증하기 위한 시크릿 키 설정
         * .parseClaimsJws(token) : JWT 토큰 파싱하고 토큰의 서명 검증. Jws<Claims> 객체 반환
         * .getBody().getSubject() : Jws<Claims> 객체에서 클레임 정보 추출(getBody()) 그 중 사용자 계정(Subject)값을 가져 옴.
         */
        return Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token).getBody().getSubject();
    }

    // Authorization Header 를 통해 인증을 한다. Request 의 헤더에 있는 Authorization 값을 통해 인증
    public String resolveToken(HttpServletRequest request) {
        return request.getHeader("Authorization");
    }

    // 토큰 검증
    public boolean validateToken(String token) {
        try{
            // 토큰 첫 부분 "BEARER " 로 시작하는 지 검사
            if(!token.substring(0, "Bearer ".length()).equalsIgnoreCase("Bearer ")){
                return false;
            } else {
                // "BEARER " 부분 제거하고 토큰 문자열만 추출
                token = token.split(" ")[1].trim();
            }
            // 토큰 파싱, 서명 검증. 시크릿 키로 서명 검증
            Jws<Claims> claims = Jwts.parserBuilder().setSigningKey(secretKey).build().parseClaimsJws(token);
            // 만료 시 false, 만료 시간 < 현재 시간
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
