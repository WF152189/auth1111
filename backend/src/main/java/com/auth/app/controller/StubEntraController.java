package com.auth.app.controller;

import com.auth.app.dto.StubTokenResponse;
import com.auth.app.model.User;
import com.auth.app.service.UserService;
import com.auth.app.stub.StubEntraService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/stub/entra")
@RequiredArgsConstructor
@Slf4j
public class StubEntraController {

    private final StubEntraService stubEntraService;
    private final UserService userService;

    /**
     * GET /stub/entra/authorize
     * 認可エンドポイント模擬（Azure Entra ID風ユーザー選択画面）
     */
    @GetMapping(value = "/authorize", produces = MediaType.TEXT_HTML_VALUE)
    public String authorize(
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "redirect_uri") String redirectUri,
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String scope,
            @RequestParam(name = "code_challenge", required = false) String codeChallenge,
            @RequestParam(name = "code_challenge_method", required = false) String codeChallengeMethod) {

        List<User> users = userService.getAllUsers();

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html lang='ja'><head><meta charset='UTF-8'><meta name='viewport' content='width=device-width, initial-scale=1.0'>");
        html.append("<title>アカウントにログイン</title>");
        html.append("<style>");
        html.append("*{margin:0;padding:0;box-sizing:border-box;}");
        html.append("body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh;}");
        html.append(".login-container{background:#fff;padding:44px;border-radius:2px;box-shadow:0 2px 6px rgba(0,0,0,0.1);width:440px;}");
        html.append(".logo{margin-bottom:24px;}");
        html.append(".logo svg{width:24px;height:24px;}");
        html.append("h1{font-size:24px;font-weight:600;color:#1b1b1b;margin-bottom:8px;}");
        html.append(".subtitle{color:#666;font-size:13px;margin-bottom:24px;}");
        html.append(".user-list{list-style:none;margin-bottom:16px;}");
        html.append(".user-item{display:flex;align-items:center;padding:12px;margin-bottom:8px;border:1px solid #e0e0e0;border-radius:2px;cursor:pointer;transition:background 0.2s;}");
        html.append(".user-item:hover{background:#f5f5f5;border-color:#0078d4;}");
        html.append(".user-avatar{width:36px;height:36px;border-radius:50%;background:#0078d4;color:#fff;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:600;margin-right:12px;}");
        html.append(".user-info{flex:1;}");
        html.append(".user-name{font-size:15px;color:#1b1b1b;font-weight:500;}");
        html.append(".user-email{font-size:13px;color:#666;margin-top:2px;}");
        html.append(".footer{margin-top:24px;padding-top:16px;border-top:1px solid #e0e0e0;text-align:center;}");
        html.append(".footer-text{font-size:12px;color:#999;}");
        html.append(".stub-notice{background:#fff3cd;border:1px solid #ffc107;border-radius:4px;padding:12px;margin-bottom:20px;font-size:12px;color:#856404;}");
        html.append("</style></head><body>");
        html.append("<div class='login-container'>");
        
        // Microsoftロゴ
        html.append("<div class='logo'>");
        html.append("<svg viewBox='0 0 24 24' xmlns='http://www.w3.org/2000/svg'>");
        html.append("<path fill='#f25022' d='M1 1h10v10H1z'/>");
        html.append("<path fill='#00a4ef' d='M1 13h10v10H1z'/>");
        html.append("<path fill='#7fba00' d='M13 1h10v10H13z'/>");
        html.append("<path fill='#ffb900' d='M13 13h10v10H13z'/>");
        html.append("</svg>");
        html.append("</div>");
        
        html.append("<h1>アカウントにログイン</h1>");
        html.append("<p class='subtitle'>テスト環境 - ユーザーを選択してください</p>");
        
        // スタブ_notice
        html.append("<div class='stub-notice'>");
        html.append("⚠️ これはEntra IDの認証画面をシミュレートするスタブ画面です");
        html.append("</div>");
        
        // ユーザーリスト
        html.append("<ul class='user-list'>");
        
        for (User user : users) {
            String initial = user.getDisplayName() != null && !user.getDisplayName().isEmpty() 
                ? user.getDisplayName().substring(0, 1).toUpperCase() 
                : "U";
            
            // onclick属性の正しいエスケープ
            html.append("<li class='user-item' onclick=\"selectUser('")
                .append(escapeHtml(user.getUserId()))
                .append("')\">");
            html.append("<div class='user-avatar'>").append(initial).append("</div>");
            html.append("<div class='user-info'>");
            html.append("<div class='user-name'>").append(escapeHtml(user.getDisplayName())).append("</div>");
            html.append("<div class='user-email'>").append(escapeHtml(user.getEmail())).append("</div>");
            html.append("</div>");
            html.append("</li>");
        }
        
        html.append("</ul>");
        
        // 隠しフォーム
        html.append("<form id='userForm' method='POST' action='/stub/entra/authorize/submit' style='display:none;'>");
        html.append("<input type='hidden' name='user_id' id='userId'/>");
        html.append("<input type='hidden' name='redirect_uri' value='").append(escapeHtml(redirectUri)).append("'/>");
        html.append("<input type='hidden' name='state' value='").append(escapeHtml(state != null ? state : "")).append("'/>");
        html.append("</form>");
        
        // フッター
        html.append("<div class='footer'>");
        html.append("<p class='footer-text'> stub-enabled | 開発環境</p>");
        html.append("</div>");
        
        html.append("</div>");
        
        // JavaScript
        html.append("<script>");
        html.append("function selectUser(userId) {");
        html.append("  document.getElementById('userId').value = userId;");
        html.append("  document.getElementById('userForm').submit();");
        html.append("}");
        html.append("</script>");
        
        html.append("</body></html>");

        return html.toString();
    }

    /**
     * POST /stub/entra/authorize/submit
     * ユーザー選択後、認可コード発行 → redirect_uriへリダイレクト
     */
    @PostMapping("/authorize/submit")
    public ResponseEntity<Void> authorizeSubmit(
            @RequestParam(name = "user_id") String userId,
            @RequestParam(name = "redirect_uri") String redirectUri,
            @RequestParam(required = false) String state) {

        String code = stubEntraService.issueAuthorizationCode(userId, redirectUri);

        String location = redirectUri + "?code=" + code;
        if (state != null && !state.isEmpty()) {
            location += "&state=" + state;
        }

        log.info("スタブ認可コード発行完了: userId={}, redirect={}", userId, redirectUri);
        return ResponseEntity.status(302).header("Location", location).build();
    }

    /**
     * POST /stub/entra/token
     * トークンエンドポイント模擬（認可コード → Entra JWT返却）
     */
    @PostMapping("/token")
    public ResponseEntity<StubTokenResponse> token(
            @RequestParam(name = "client_id", required = false) String clientId,
            @RequestParam(name = "grant_type", required = false) String grantType,
            @RequestParam String code,
            @RequestParam(name = "redirect_uri", required = false) String redirectUri,
            @RequestParam(name = "code_verifier", required = false) String codeVerifier) {

        // 認可コードを検証し、JWTを取得
        String entraJwt = stubEntraService.exchangeCodeForEntraJwt(code);

        // トークンレスポンス構築
        StubTokenResponse tokenResponse = StubTokenResponse.builder()
                .tokenType("Bearer")
                .idToken(entraJwt)
                .expiresIn(3600)
                .build();

        log.info("スタブEntra JWT発行完了");
        return ResponseEntity.ok(tokenResponse);
    }

    /**
     * GET /stub/entra/users
     * スタブ用テストユーザー一覧（フロントエンド参照用）
     */
    @GetMapping("/users")
    public ResponseEntity<List<?>> getUsers() {
        List<?> users = userService.getAllUsers().stream()
                .map(u -> java.util.Map.of(
                        "userId", u.getUserId(),
                        "email", u.getEmail(),
                        "displayName", u.getDisplayName()
                ))
                .collect(Collectors.toList());
        return ResponseEntity.ok(users);
    }

    private String escapeHtml(String input) {
        if (input == null) return "";
        return input.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#39;");
    }
}
