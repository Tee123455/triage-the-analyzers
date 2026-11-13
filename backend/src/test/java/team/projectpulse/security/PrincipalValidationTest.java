package team.projectpulse.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import team.projectpulse.instructor.converter.InstructorToInstructorDtoConverter;
import team.projectpulse.student.converter.StudentToStudentDtoConverter;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class PrincipalValidationTest {

    @Test
    void loginRejectsMissingPrincipalBeforeConvertingUserOrIssuingToken() {
        JwtProvider provider = mock(JwtProvider.class);
        StudentToStudentDtoConverter students = mock(StudentToStudentDtoConverter.class);
        InstructorToInstructorDtoConverter instructors = mock(InstructorToInstructorDtoConverter.class);
        AuthService service = new AuthService(provider, students, instructors);
        var authentication = UsernamePasswordAuthenticationToken.unauthenticated(null, null);

        assertThatThrownBy(() -> service.createLoginInfo(authentication))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(provider, students, instructors);
    }

    @Test
    void tokenCreationRejectsMissingPrincipalBeforeEncoding() {
        JwtEncoder encoder = mock(JwtEncoder.class);
        JwtProvider provider = new JwtProvider(encoder);
        var authentication = UsernamePasswordAuthenticationToken.unauthenticated(null, null);

        assertThatThrownBy(() -> provider.createToken(authentication))
                .isInstanceOf(BadCredentialsException.class);
        verifyNoInteractions(encoder);
    }
}
