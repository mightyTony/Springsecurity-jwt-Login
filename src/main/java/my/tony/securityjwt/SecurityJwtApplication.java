package my.tony.securityjwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SecurityJwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecurityJwtApplication.class, args);

        // 시크릿 키 생성
        /*
        int keyLength = 32;

        // 안전한 난수 생성
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[keyLength];
        secureRandom.nextBytes(keyBytes);

        // 바이트 배열을 Base64로 인코딩하여 시크릿 키 생성
        String jwtSecretKey = Base64.getEncoder().encodeToString(keyBytes);

        System.out.println("JWT Secret Key: " + jwtSecretKey);
        */
    }

}
