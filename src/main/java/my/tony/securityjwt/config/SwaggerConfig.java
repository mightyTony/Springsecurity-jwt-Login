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

@Configuration
@EnableSwagger2
public class SwaggerConfig {

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .useDefaultResponseMessages(true) // Swagger 에서 제공해주는 기본 응답 코드를 표시할 것이면 true
                .apiInfo(apiInfo())
                .select()
//                .apis(RequestHandlerSelectors.basePackage(RequestHandlerSelectors))
                .apis(RequestHandlerSelectors.any()) // 모든 컨트롤러 문서화
                .paths(PathSelectors.any()) // 모든 경로를 문서화
                .build()
                .securityContexts(Arrays.asList(securityContext()))
                .securitySchemes(Arrays.asList(apiKey()));
    }

    // 인증 방식 설정
    private SecurityContext securityContext() {
        return SecurityContext.builder()
                .securityReferences(defaultAuth())
                .build();
    }

    private List<SecurityReference> defaultAuth() {
        AuthorizationScope authorizationScope = new AuthorizationScope("global", "accessEverything");
        AuthorizationScope[] authorizationScopes = new AuthorizationScope[1];
        authorizationScopes[0] = authorizationScope;
        return Arrays.asList(new SecurityReference("Authorization", authorizationScopes));
    }

    public ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("Spring boot Jwt REST API TEST")
                .description(" 내가 만든 JWT 문서 ")
                .version("1.0")
                .build();
    }

    private ApiKey apiKey() {
        return new ApiKey("Authorization", "Bearer", "header");
    }
}
