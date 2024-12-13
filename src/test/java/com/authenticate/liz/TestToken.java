package com.authenticate.liz;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCrypt;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;


@ExtendWith(MockitoExtension.class)
public class TestToken {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @InjectMocks
    private RefreshTokenService refreshTokenService;

    final byte[] jwtKey = new byte[]{-91, -33, 62, -83, -94, 105, -119, 53, -117, -51, 15, 36, 47, -46, -110, 3, -128, -9, 59, -100, -20, -58, 43, 69, 60, 75, -16, 29, 59, 89, 3, -77, -32, -5, 62, -93, 48, 69, 28, 111, -46, -18, 93, 7, 104, 51, -62, 70, 47, 112, 3, 106, -84, 13, 52, -40, 62, 89, 96, 81, 16, 81, -86, -93};

    @Test
    public void testDropAccessToken() {
        UUID userId = UUID.randomUUID();
        String ipAddress = "149.6.9.2";
        String token = refreshTokenService.dropAccessToken(userId, ipAddress);
        assertNotNull(token);

        Claims claims = Jwts.parser().setSigningKey(jwtKey).parseClaimsJws(token).getBody();
        assertNotNull(claims);
        assertEquals(userId.toString(), claims.get("user Id"));
        assertEquals(ipAddress, claims.get("IP address"));
    }

    @Test
    public void testExamRefreshToken() {
        String token = "token";
        String hash = BCrypt.hashpw(token, BCrypt.gensalt());
        boolean result = RefreshTokenService.examRefreshToken(token, hash);
        assertTrue(result);
    }
}
