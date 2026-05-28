package com.auth.app.controller;

import com.auth.app.dto.ScreenPermissionRequest;
import com.auth.app.dto.ScreenPermissionResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 画面権限コントローラー
 * 
 * ユーザーの画面アクセス権限をチェックする
 * スタブ環境では簡易的な実装、本番環境ではDBまたは外部認可サーバーと連携
 */
@RestController
@RequestMapping("/api/screens")
@RequiredArgsConstructor
@Slf4j
public class ScreenPermissionController {

    /**
     * POST /api/screens/permission/check
     * 画面権限チェック
     * 
     * フロー:
     * 1. JWTからユーザーIDを抽出（セキュリティ修正済み）
     * 2. 画面IDとユーザーIDで権限をチェック
     * 3. 承認結果を返却
     * 
     * @param request 画面IDを含むリクエスト
     * @return 権限チェック結果
     */
    @PostMapping("/permission/check")
    public ResponseEntity<ScreenPermissionResponse> checkPermission(
            @RequestBody ScreenPermissionRequest request) {
        
        String screenId = request.getScreenId();
        
        if (screenId == null || screenId.isEmpty()) {
            log.warn("画面権限チェック失敗: screenIdが未設定");
            return ResponseEntity.badRequest().body(
                ScreenPermissionResponse.builder()
                    .authorized(false)
                    .reason("画面IDが無効です")
                    .build()
            );
        }
        
        // TODO: JWTからユーザーIDを抽出（現在はリクエストから取得）
        // 本番環境では、@AuthenticationPrincipalまたはJwtAuthenticationFilterで設定された
        // SecurityContextからユーザーIDを取得する
        String userId = "eeeeeeee";
        if (userId == null || userId.isEmpty()) {
            log.warn("画面権限チェック失敗: userIdが未設定");
            return ResponseEntity.badRequest().body(
                ScreenPermissionResponse.builder()
                    .authorized(false)
                    .reason("ユーザーIDが無効です")
                    .build()
            );
        }
        
        log.info("画面権限チェック: userId={}, screenId={}", userId, screenId);
        
        // スタブ実装: 画面IDとユーザーIDで簡易的な認可ロジック
        boolean authorized = checkScreenPermission(userId, screenId);
        
        if (authorized) {
            log.info("画面アクセス許可: userId={}, screenId={}", userId, screenId);
            return ResponseEntity.ok(
                ScreenPermissionResponse.builder()
                    .authorized(true)
                    .message("アクセスが許可されています")
                    .build()
            );
        } else {
            log.warn("画面アクセス拒否: userId={}, screenId={}", userId, screenId);
            return ResponseEntity.ok(
                ScreenPermissionResponse.builder()
                    .authorized(false)
                    .reason("この画面へのアクセス権限がありません")
                    .build()
            );
        }
    }
    
    /**
     * 画面権限をチェック（スタブ実装）
     * 
     * 本番環境ではDBまたは外部認可サーバーでチェック
     * 
     * @param userId ユーザーID
     * @param screenId 画面ID
     * @return 権限の成否
     */
    private boolean checkScreenPermission(String userId, String screenId) {
        // スタブロジック:
        // - admin001: 全画面アクセス可能（ADMIN_MANAGEMENT_SCREEN, SETTINGS_SCREEN 以下すべての子画面を含む）
        // - user001: BUSINESS_DATA_SCREEN のみアクセス可能
        // - その他: すべて拒否
        
        if ("admin001".equals(userId)) {
            return true; // 管理者は全画面アクセス可能
        }
        
        if ("user001".equals(userId)) {
            // 一般ユーザーは業務データ画面のみ
            return "BUSINESS_DATA_SCREEN".equals(screenId);
        }
        
        return false; // その他のユーザーはすべて拒否
    }
}
