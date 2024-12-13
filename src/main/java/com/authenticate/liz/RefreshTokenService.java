package com.authenticate.liz;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    private final byte[] jwtKey = new byte[]{-91, -33, 62, -83, -94, 105, -119, 53, -117, -51, 15, 36, 47, -46, -110, 3, -128, -9, 59, -100, -20, -58, 43, 69, 60, 75, -16, 29, 59, 89, 3, -77, -32, -5, 62, -93, 48, 69, 28, 111, -46, -18, 93, 7, 104, 51, -62, 70, 47, 112, 3, 106, -84, 13, 52, -40, 62, 89, 96, 81, 16, 81, -86, -93};
    private final int accessTokenValidityInSeconds = 2700;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public Optional<RefreshToken> findByUserIdAndIpAddress(UUID userId, String ipAddress) {
        return refreshTokenRepository.findByUserIdAndIpAddress(userId, ipAddress);
    }

    public String dropAccessToken(UUID userId, String ipAddress) {
        return Jwts.builder().claim("user Id", userId).claim("IP address", ipAddress)
                .setIssuedAt(new Date()).setExpiration(new Date(System.currentTimeMillis() + accessTokenValidityInSeconds * 1000))
                .signWith(SignatureAlgorithm.HS512, jwtKey).compact();
    }

    public String dropRefreshToken(UUID userId, String ipAddress) {
        String refreshToken = UUID.randomUUID().toString();
        String hashRefreshToken = BCrypt.hashpw(refreshToken, BCrypt.gensalt());

        RefreshToken token = new RefreshToken();
        token.setUserId(userId);
        token.setRefreshTokenHash(hashRefreshToken);
        token.setIpAddress(ipAddress);
        refreshTokenRepository.save(token);

        return refreshToken;
    }

    public static boolean examRefreshToken(String refreshToken, String storeHash) {
        return BCrypt.checkpw(refreshToken, storeHash);
    }
}
