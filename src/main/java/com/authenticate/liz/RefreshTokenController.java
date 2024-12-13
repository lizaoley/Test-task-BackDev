package com.authenticate.liz;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/auth")
public class RefreshTokenController {

    @Autowired
    private RefreshTokenService refreshTokenService;

    public static class Token {
        public String accessToken;
        public String refreshToken;

        public Token(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
    }

    @PostMapping("/login")
    public Token login(@RequestParam UUID userId, @RequestHeader String ipAddress) {
        String accessToken = refreshTokenService.dropAccessToken(userId, ipAddress);
        String refreshToken = refreshTokenService.dropRefreshToken(userId, ipAddress);

        return new Token(accessToken, refreshToken);
    }

    @PostMapping("/refresh")
    public Token refresh(@RequestParam String refreshToken, @RequestParam UUID userId, @RequestHeader String ipAddress) {
        var storeRefreshToken = refreshTokenService.findByUserIdAndIpAddress(userId, ipAddress);
        if (storeRefreshToken.isEmpty() || !RefreshTokenService.examRefreshToken(refreshToken, storeRefreshToken.get().getRefreshTokenHash())) {
            throw new RuntimeException("Недействительный refresh token");
        }
        String accessToken = refreshTokenService.dropAccessToken(userId, ipAddress);
        return new Token(accessToken, refreshToken);
    }
}
