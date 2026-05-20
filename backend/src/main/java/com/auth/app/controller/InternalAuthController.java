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
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Slf4j
public class InternalAuthController {

    /**
     * POST /api/auth/validate
     * Entra ID subクレーム検証API
     * 
     * フロー:
     * 1. リクエストボディからsubを取得（Entra ID token内のoid）
     * 2. subのフォーマット・有効性を検証
     * 3. 業務システムへの認可是否存在をチェック（1秒待機）
     * 4. 検証結果を返す
     * 
     * @param request { "sub": "ユーザー識別子" }
     * @return 検証結果
     */
    @PostMapping("/validate")
    public ResponseEntity<ValidationResponse> validate(@RequestBody ValidationRequest request) {
        String sub = request.getSub();
        
        log.info("sub検証開始: sub={}", sub);
        
        // Step 1: subの必須チェック
        if (sub == null || sub.isBlank()) {
            log.warn("subが空です");
            return ResponseEntity.badRequest().body(
                ValidationResponse.builder()
                    .success(false)
                    .message("subは必須です")
                    .build()
            );
        }
        
        // Step 2: subのフォーマット検証（GUID形式であることを確認）
        if (!isValidSubFormat(sub)) {
            log.warn("subフォーマットが無効: sub={}", sub);
            return ResponseEntity.badRequest().body(
                ValidationResponse.builder()
                    .success(false)
                    .message("subのフォーマットが無効です")
                    .build()
            );
        }
        
        // Step 3: 認可チェック（1秒待機）
        try {
            log.debug("認可チェック開始: sub={}", sub);
            Thread.sleep(1000);
            log.debug("認可チェック完了: sub={}", sub);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("待機中に割り込みが発生: sub={}", sub);
            throw AuthException.internalAuthFailed();
        }
        
        // Step 4: 検証成功を返す
        log.info("sub検証成功: sub={}", sub);
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
        private String sub;
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