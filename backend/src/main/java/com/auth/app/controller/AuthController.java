package com.auth.app.controller;

import com.auth.app.dto.AuthResponse;
import com.auth.app.exception.AuthException;
import com.auth.app.service.AuthenticationService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
     * POST /auth/logout
     * ログアウト処理
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            HttpServletRequest request,
            HttpServletResponse response) {

        authenticationService.logout();

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
}
