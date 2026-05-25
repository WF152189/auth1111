package com.auth.app.controller;

import com.auth.app.dto.AuthResponse;
import com.auth.app.exception.AuthException;
import com.auth.app.service.AuthenticationService;
import com.auth.app.service.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
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
    private final JwtService jwtService;
    
    @Value("${stub.enabled}")
    private boolean stubEnabled;

    /**
     * POST /auth/verify
     * Entra JWT検証 → 業務JWT発行
     * 
     * 設計:
     * - 成功: 200 + { success: true, userId, email, ... }
     * - 失敗: 例外スロー → GlobalExceptionHandler が処理
     */
    @PostMapping("/verify")
    public ResponseEntity<AuthResponse> verify(
            @RequestHeader("Authorization") String authHeader,
            HttpServletResponse response) {

        // スタブモード: 認証成功としてレスポンスを返す
        if (stubEnabled) {
            log.info("[スタブ] 認証成功としてレスポンスを返します");
            
            // ダミーの業務JWT生成（JWT形式で生成）
            String dummyToken = jwtService.generateToken(
                    "stub-user-12345",
                    "testuser@example.com",
                    "テストユーザー",
                    java.util.List.of("USER"),
                    java.util.List.of("read", "write")
            );
            
            // レスポンスヘッダーに設定
            response.addHeader("Authorization", "Bearer " + dummyToken);
            
            // スタブ用レスポンス
            return ResponseEntity.ok(AuthResponse.success(
                    "stub-user-12345",
                    "testuser@example.com",
                    "テストユーザー",
                    java.util.List.of("USER"),
                    java.util.List.of("read", "write")
            ));
        }

        // 本番モード: 例外処理は GlobalExceptionHandler に委譲
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
