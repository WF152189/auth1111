package com.auth.app.controller;

import com.auth.app.dto.AuthResponse;
import com.auth.app.exception.AuthException;
import com.auth.app.service.AuthenticationService;
import com.auth.app.service.RefreshTokenService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;

/**
 * 認証コントローラー
 * 
 * 設計方針:
 * - 常にHTTP 200を返す
 * - 業務エラーはbodyのsuccess=falseで表現
 * - Entra検証失敗、サーバーエラーに関係なく200を返す
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class AuthController {

    private final AuthenticationService authenticationService;
    private final RefreshTokenService refreshTokenService;

    private static final String RT_COOKIE_NAME = "refresh_token";

    /**
     * POST /auth/verify
     * Entra JWT検証 → 業務JWT発行
     * 
     * 設計:
     * - 成功: 200 + { success: true, userId, email, ... }
     * - 失敗: 200 + { success: false, message: "..." }
     */
    @PostMapping("/verify")
    public ResponseEntity<AuthResponse> verify(
            @RequestHeader("Authorization") String authHeader,
            HttpServletResponse response) {

        try {
            String entraJwt = extractBearerToken(authHeader);
            AuthResponse authResponse = authenticationService.verifyAndIssueTokens(entraJwt);

            // RT発行・Cookie設定
            String rawRt = refreshTokenService.createRefreshToken(authResponse.getUserId());
            addRefreshTokenCookie(response, rawRt);

            // アクセストークンをレスポンスヘッダーに設定
            response.addHeader("Authorization", "Bearer " + authResponse.getToken());

            log.info("認証・JWT発行完了: userId={}", authResponse.getUserId());
            
            // 成功レスポンスを返す
            return ResponseEntity.ok(AuthResponse.success(
                    authResponse.getUserId(),
                    authResponse.getEmail(),
                    authResponse.getDisplayName(),
                    authResponse.getRoles(),
                    authResponse.getPermissions()
            ));
            
        } catch (AuthException e) {
            // Entra検証失敗は200で返す
            log.warn("Entra JWT検証失敗: {}", e.getMessage());
            return ResponseEntity.ok(AuthResponse.failure(e.getMessage()));
            
        } catch (Exception e) {
            // サーバーエラーも200で返す
            log.error("予期せぬエラー: {}", e.getMessage(), e);
            return ResponseEntity.ok(AuthResponse.failure("サーバーエラー"));
        }
    }

    /**
     * POST /auth/refresh
     * RT更新 → 新規業務JWT + 新規RT発行（RTローテーション）
     */
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(
            HttpServletRequest request,
            HttpServletResponse response) {

        String oldRawRt = extractRefreshTokenFromCookie(request);
        if (oldRawRt == null) {
            return ResponseEntity.ok(AuthResponse.failure("RefreshTokenがありません"));
        }

        try {
            AuthResponse authResponse = authenticationService.refreshTokens(oldRawRt);

            // RTローテーション
            String newRawRt = refreshTokenService.rotateRefreshToken(oldRawRt, authResponse.getUserId());
            addRefreshTokenCookie(response, newRawRt);

            // アクセストークンをレスポンスヘッダーに設定
            response.addHeader("Authorization", "Bearer " + authResponse.getToken());

            log.info("トークン更新完了: userId={}", authResponse.getUserId());
            
            return ResponseEntity.ok(AuthResponse.success(
                    authResponse.getUserId(),
                    authResponse.getEmail(),
                    authResponse.getDisplayName(),
                    authResponse.getRoles(),
                    authResponse.getPermissions()
            ));
            
        } catch (AuthException e) {
            log.warn("RefreshToken検証失敗: {}", e.getMessage());
            return ResponseEntity.ok(AuthResponse.failure(e.getMessage()));
            
        } catch (Exception e) {
            log.error("予期せぬエラー: {}", e.getMessage(), e);
            return ResponseEntity.ok(AuthResponse.failure("サーバーエラー"));
        }
    }

    /**
     * POST /auth/logout
     * RT無効化・Cookie削除
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        String rawRt = extractRefreshTokenFromCookie(request);
        if (rawRt != null) {
            authenticationService.logout(rawRt);
        }

        // Cookie削除
        deleteRefreshTokenCookie(response);

        log.info("ログアウト完了");
        return ResponseEntity.ok().build();
    }

    // --- ヘルパーメソッド ---

    private String extractBearerToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw AuthException.entraTokenInvalid();
        }
        return authHeader.substring(7);
    }

    private String extractRefreshTokenFromCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        return Arrays.stream(request.getCookies())
                .filter(c -> RT_COOKIE_NAME.equals(c.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    private void addRefreshTokenCookie(HttpServletResponse response, String rawRt) {
        Cookie cookie = new Cookie(RT_COOKIE_NAME, rawRt);
        cookie.setHttpOnly(true);
        cookie.setPath("/auth");
        cookie.setMaxAge(28800); // 8時間
        // cookie.setSecure(true); // HTTPS環境で有効化
        response.addCookie(cookie);
    }

    private void deleteRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(RT_COOKIE_NAME, "");
        cookie.setHttpOnly(true);
        cookie.setPath("/auth");
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }
}