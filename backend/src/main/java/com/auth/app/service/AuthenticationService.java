package com.auth.app.service;

import com.auth.app.dto.AuthResponse;
import com.auth.app.dto.UserPermissionInfo;
import com.auth.app.exception.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * 認証サービス
 * 
 * 責務:
 * 1. Entra ID JWT検証 → 業務JWT発行
 * 2. ログアウト
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthenticationService {

    private final JwtService jwtService;
    private final UserService userService;
    private final EntraIdJwtValidator entraIdJwtValidator;

    /**
     * Entra JWT検証 → 業務JWT発行
     * 
     * フロー:
     * 1. EntraIdJwtValidatorでEntra JWT検証（署名・iss・aud・exp）
     * 2. UserServiceでユーザー権限照会
     * 3. JwtServiceで業務JWT生成
     */
    public AuthResponse verifyAndIssueTokens(String entraJwt) {
        log.info("=== 認証フロー開始 ===");
        
        // Step 1: Entra JWT検証（MSAL4J + Nimbus-JWT）
        var claims = entraIdJwtValidator.validateEntraIdToken(entraJwt);
        String userId = claims.getSubject();
        log.info("Entra JWT検証成功: userId={}", userId);

        // Step 2: ユーザー権限照会
        UserPermissionInfo permInfo = userService.getUserPermissionInfo(userId);
        if (permInfo == null) {
            log.warn("ユーザー未登録: userId={}", userId);
            throw AuthException.userNotFound();
        }

        // Step 3: 業務JWT生成
        String businessJwt = jwtService.generateToken(
                permInfo.getUserId(),
                permInfo.getEmail(),
                permInfo.getDisplayName(),
                permInfo.getRoles(),
                permInfo.getPermissions()
        );

        log.info("業務JWT発行完了: userId={}, roles={}", userId, permInfo.getRoles());
        log.info("=== 認証フロー完了 ===");

        return AuthResponse.builder()
                .token(businessJwt)
                .userId(permInfo.getUserId())
                .email(permInfo.getEmail())
                .displayName(permInfo.getDisplayName())
                .roles(permInfo.getRoles())
                .permissions(permInfo.getPermissions())
                .build();
    }

    /**
     * ログアウト
     */
    public void logout() {
        log.info("ログアウト完了");
    }
}
