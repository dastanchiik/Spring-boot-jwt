package springsecurityjsonwebtoken.api;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import springsecurityjsonwebtoken.dto.request.LoginRequest;
import springsecurityjsonwebtoken.dto.request.UserRegisterRequest;
import springsecurityjsonwebtoken.dto.response.JWTResponse;
import springsecurityjsonwebtoken.service.AuthService;

import javax.annotation.security.PermitAll;

@RestController
@RequiredArgsConstructor
public class AuthApi {

    private final AuthService authService;

    @PostMapping("register")
    @PermitAll
    public JWTResponse registrationPerson(@RequestBody UserRegisterRequest userRegisterRequest) {
        return authService.registerUser( userRegisterRequest );
    }

    @PostMapping("login")
    @PermitAll
    public JWTResponse performLogin(@RequestBody LoginRequest loginResponse) {
        return authService.authenticate( loginResponse );
    }

}
