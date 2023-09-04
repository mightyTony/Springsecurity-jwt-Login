package my.tony.securityjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.ApiKey;
import springfox.documentation.service.AuthorizationScope;
import springfox.documentation.service.SecurityReference;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Arrays;
import java.util.List;


/**
 *  스웨거(API 문서 라이브러리) 설정
 */
@Configuration
@EnableSwagger2
public class SwaggerConfig {

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .select()
//                .apis(RequestHandlerSelectors.basePackage(RequestHandlerSelectors))
                .apis(RequestHandlerSelectors.any()) // 모든 컨트롤러 문서화
                .paths(PathSelectors.any()) // 모든 경로를 문서화
                .build()
                .securityContexts(Arrays.asList(securityContext())) // 인증 토큰 설정
                .securitySchemes(Arrays.asList(apiKey())); // 보안 컨텍스트 설정
    }

    // 인증 방식 설정
    private SecurityContext securityContext() {
        return SecurityContext.builder()
                .securityReferences(defaultAuth())
                .build();
    }

    public ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("Spring boot Jwt REST API TEST")
                .description(" 내가 만든 JWT 문서 ")
                .version("1.0")
                .build();
    }

    /*private List<SecurityReference> defaultAuth() {
        AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return Arrays.asList(new SecurityReference("Authorization", authorizationScopes));
    }*/

    /*private ApiKey apiKey() {
        return new ApiKey("Authorization", "Bearer", "header");
    }*/

    private List<SecurityReference> defaultAuth() {
        return Arrays.asList(
                new SecurityReference("JWT", new AuthorizationScope[0]) // "JWT" 보안 참조를 사용하여 인증 스코프 설정
        );
    }


    // API 키 입력 칸 설정
    private ApiKey apiKey() {
        // 입력 칸 이름 : JWT, HTTP 헤더 이름 : "Authorization", "header" : JWT가 헤더에 포함되야함을 표시
        return new ApiKey("JWT", "Authorization", "header"); // "JWT"라는 이름으로 "Authorization" 헤더에 JWT 토큰을 추가
    }

}
