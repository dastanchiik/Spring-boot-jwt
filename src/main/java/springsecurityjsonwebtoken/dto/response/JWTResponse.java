package springsecurityjsonwebtoken.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import springsecurityjsonwebtoken.model.Role;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class JWTResponse {

    private String email;
    private String token;
    private String message;
    private Role role;
}