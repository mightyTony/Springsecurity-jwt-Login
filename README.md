시큐리티 구 버전 방식의 Websecurityconfigureradapter 가 아닌 FilterChain을 통해 구현
===========================================

# 기능
===========
### 1. JWT을 통해 Header에서 토큰을 통해 접근 인증,인가 
### 2. Bcrypt Password Encode

# 정상 동작 순서 
===========
### 1. localhost:8080/swagger-ui/ 접속
### 2. 회원 가입 
### 3. 로그인 JSON(id, paswword)만 입력
### 4. 로그인 성공(200) 일 시 Response 에 토큰이 부여 됨. 토큰 복사 
### 5. 스웨거 창 우측 상단에 Authorize 클릭 
### 6. 토큰 입력 란에 "Bearer 복사한 토큰 값" 입력  (띄어쓰기 확인)
### 7. 권한이 필요한 api(user/get, admin/get) 으로 테스트 
### 8. 성공 

# 추후 해결 해야 할 일
==========
##  1. Login API에서 Response로 토큰을 주는데 어떻게 Header로 값을 주는 지 확인 해야 함.
##  2. 클라이언트는 해당 값을 어떻게 어디서 저장 하는지 확인 해야 함.
