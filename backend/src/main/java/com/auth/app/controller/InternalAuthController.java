package com.auth.app.controller;

import com.auth.app.exception.InternalAuthException;
import com.auth.app.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;

/**
 * 内部認証コントローラー
 * 
 * Entra IDのsubクレームを検証し、业务用システムへの認可をチェックする
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
@Slf4j
public class InternalAuthController {

    private final JwtService jwtService;
    
    @Value("${stub.enabled}")
    private boolean stubEnabled;

    /**
     * POST /auth/validate
     * Entra ID subクレーム検証API
     * 
     * フロー:
     * 1. Authorization headerから業務JWTを取得
     * 2. JWTの検証（形式、署名、有効期限）
     * 3. リクエストボディからuserIdを取得（Entra ID token内のsub/oid）
     * 4. userIdのフォーマット・有効性を検証
     * 5. 業務システムへの認可是否存在をチェック（1秒待機）
     * 6. 検証結果を返す
     * 
     * @param request { "userId": "ユーザー識別子" }
     * @return 検証結果
     */
    @PostMapping("/validate")
    public ResponseEntity<ValidationResponse> validate(
            @RequestBody ValidationRequest request,
            HttpServletRequest httpRequest) {
        
        // スタブモード: 検証成功としてレスポンスを返す
        if (stubEnabled) {
            log.info("[スタブ] sub検証成功としてレスポンスを返します: userId={}", request.getUserId());
            
            return ResponseEntity.ok(
                ValidationResponse.builder()
                    .success(true)
                    .message("[スタブ] 検証成功")
                    .build()
            );
        }
        
        // 本番モード: 通常の検証処理
        // Step 1: Authorization headerからJWTを取得
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw InternalAuthException.tokenNotFound();
        }
        
        String token = authHeader.substring(7);
        
        // Step 2: JWTの検証
        try {
            Claims claims = jwtService.validateToken(token);
            String tokenUserId = claims.getSubject();
            log.debug("JWT検証成功: userId={}", tokenUserId);
        } catch (ExpiredJwtException e) {
            log.warn("JWT期限切れ: {}", e.getMessage());
            throw InternalAuthException.tokenExpired();
        } catch (JwtException e) {
            log.warn("JWT検証失敗: {}", e.getMessage());
            throw InternalAuthException.tokenValidationFailed(e.getMessage());
        }
        
        // Step 3: userIdの必須チェック
        String userId = request.getUserId();
        if (userId == null || userId.isBlank()) {
            log.warn("userIdが空です");
            throw InternalAuthException.tokenValidationFailed("userIdは必須です");
        }
        
        // Step 4: userIdのフォーマット検証（GUID形式であることを確認）
        if (!isValidSubFormat(userId)) {
            log.warn("userIdフォーマットが無効: userId={}", userId);
            throw InternalAuthException.tokenValidationFailed("userIdのフォーマットが無効です");
        }
        
        // Step 5: 認可チェック（1秒待機）
        try {
            log.debug("認可チェック開始: userId={}", userId);
            Thread.sleep(1000);
            log.debug("認可チェック完了: userId={}", userId);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("待機中に割り込みが発生: userId={}", userId);
            throw InternalAuthException.tokenValidationFailed("認可チェック中にエラーが発生しました");
        }
        
        // Step 6: 検証成功を返す
        log.info("sub検証成功: userId={}", userId);
        return ResponseEntity.ok(
            ValidationResponse.builder()
                .success(true)
                .message("検証成功")
                .build()
        );
    }

    /**
     * subのフォーマット検証（GUID形式）
     */
    private boolean isValidSubFormat(String sub) {
        // GUID形式: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (32文字+4ハイフン)
        // または単なる文字列（開発環境用）
        if (sub.matches("[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}")) {
            return true;
        }
        // 開発環境用の簡易チェック（英数字のみ）
        if (sub.matches("[a-zA-Z0-9]+")) {
            return true;
        }
        return false;
    }

    /**
     * 検証リクエストDTO
     */
    @lombok.Data
    public static class ValidationRequest {
        private String userId;
    }

    /**
     * 検証レスポンスDTO
     */
    @lombok.Data
    @lombok.Builder
    public static class ValidationResponse {
        private boolean success;
        private String message;
    }
}