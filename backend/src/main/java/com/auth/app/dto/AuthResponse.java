package com.auth.app.dto;

import lombok.*;
import java.util.List;

/**
 * 認証レスポンスDTO
 * 
 * 設計方針:
 * - 常にHTTP 200を返す
 * - 業務エラーはbodyのsuccess=falseで表現
 * - 成功時: { success: true, userId, email, ... }
 * - 失敗時: { success: false, message: "エラーメッセージ" }
 */
@Getter @Setter
@NoArgsConstructor @AllArgsConstructor
@Builder
public class AuthResponse {
    // 成功フラグ（デフォルトtrue）
    @Builder.Default
    private boolean success = true;
    
    // エラーメッセージ（失敗時のみ使用）
    private String message;
    
    // ユーザー情報（成功時のみ使用）
    private String userId;
    private String email;
    private String displayName;
    private List<String> roles;
    private List<String> permissions;
    
    // 業務JWT（内部操作用、JSONシリアライズ时就外す）
    @com.fasterxml.jackson.annotation.JsonIgnore
    private String token;
    
    /**
     * 成功レスポンスを生成
     */
    public static AuthResponse success(String userId, String email, String displayName, 
            List<String> roles, List<String> permissions) {
        return AuthResponse.builder()
                .success(true)
                .userId(userId)
                .email(email)
                .displayName(displayName)
                .roles(roles)
                .permissions(permissions)
                .build();
    }
    
    /**
     * 失敗レスポンスを生成
     */
    public static AuthResponse failure(String message) {
        return AuthResponse.builder()
                .success(false)
                .message(message)
                .build();
    }
}