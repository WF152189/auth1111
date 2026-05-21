package com.auth.app.stub;

import com.auth.app.model.StubAuthCode;
import com.auth.app.model.User;
import com.auth.app.repository.StubAuthCodeRepository;
import com.auth.app.repository.UserRepository;
import com.auth.app.service.JwtService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class StubEntraService {

    private final StubAuthCodeRepository authCodeRepository;
    private final UserRepository userRepository;
    private final JwtService jwtService;

    @Value("${stub.entra.issuer}")
    private String entraIssuer;

    @Value("${stub.entra.client-id}")
    private String clientId;

    /**
     * 認可コードを発行し、DBに保存する
     */
    public String issueAuthorizationCode(String userId, String redirectUri) {
        String code = UUID.randomUUID().toString().replace("-", "");

        StubAuthCode authCode = StubAuthCode.builder()
                .code(code)
                .userId(userId)
                .redirectUri(redirectUri)
                .createdAt(LocalDateTime.now())
                .expiresAt(LocalDateTime.now().plusMinutes(5))
                .build();
        authCodeRepository.save(authCode);

        log.info("スタブ認可コード発行: userId={}, code={}", userId, code.substring(0, 8) + "...");
        return code;
    }

    /**
     * 認可コードを検証し、Entra JWTを生成して返す
     * @return String entraJwt
     */
    public String exchangeCodeForEntraJwt(String code) {
        Optional<StubAuthCode> authCodeOpt = authCodeRepository.findById(code);
        if (authCodeOpt.isEmpty()) {
            throw new RuntimeException("無効な認可コードです");
        }

        StubAuthCode authCode = authCodeOpt.get();
        if (authCode.getExpiresAt().isBefore(LocalDateTime.now())) {
            authCodeRepository.delete(authCode);
            throw new RuntimeException("認可コードの有効期限が切れています");
        }

        // 認可コードを使用済みとして削除
        authCodeRepository.delete(authCode);

        // ユーザー情報取得
        User user = userRepository.findById(authCode.getUserId())
                .orElseThrow(() -> new RuntimeException("ユーザーが見つかりません"));

        // Entra JWT生成
        String entraJwt = jwtService.generateEntraJwt(
                user.getUserId(),
                user.getEmail(),
                user.getDisplayName(),
                entraIssuer,
                clientId
        );

        log.info("スタブEntra JWT発行: userId={}", user.getUserId());
        return entraJwt;
    }
}
