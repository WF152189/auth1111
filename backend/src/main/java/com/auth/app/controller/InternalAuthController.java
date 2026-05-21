package com.auth.app.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.auth.app.exception.AuthException;

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

    /**
     * POST /auth/validate
     * Entra ID subクレーム検証API
     * 
     * フロー:
     * 1. リクエストボディからuserIdを取得（Entra ID token内のsub/oid）
     * 2. userIdのフォーマット・有効性を検証
     * 3. 業務システムへの認可是否存在をチェック（1秒待機）
     * 4. 検証結果を返す
     * 
     * @param request { "userId": "ユーザー識別子" }
     * @return 検証結果
     */
    @PostMapping("/validate")
    public ResponseEntity<ValidationResponse> validate(@RequestBody ValidationRequest request) {
        String userId = request.getUserId();
        
        log.info("sub検証開始: userId={}", userId);
        
        // Step 1: userIdの必須チェック
        if (userId == null || userId.isBlank()) {
            log.warn("userIdが空です");
            return ResponseEntity.badRequest().body(
                ValidationResponse.builder()
                    .success(false)
                    .message("userIdは必須です")
                    .build()
            );
        }
        
        // Step 2: userIdのフォーマット検証（GUID形式であることを確認）
        if (!isValidSubFormat(userId)) {
            log.warn("userIdフォーマットが無効: userId={}", userId);
            return ResponseEntity.badRequest().body(
                ValidationResponse.builder()
                    .success(false)
                    .message("userIdのフォーマットが無効です")
                    .build()
            );
        }
        
        // Step 3: 認可チェック（1秒待機）
        try {
            log.debug("認可チェック開始: userId={}", userId);
            Thread.sleep(1000);
            log.debug("認可チェック完了: userId={}", userId);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("待機中に割り込みが発生: userId={}", userId);
            throw AuthException.internalAuthFailed();
        }
        
        // Step 4: 検証成功を返す
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