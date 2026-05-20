package com.auth.app.service;

import com.auth.app.exception.AuthException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jwt.proc.JWTClaimsSetVerifier;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

/**
 * Entra ID JWT検証サービス（Nimbus-JWT v9.x）
 * 
 * 検証項目（OIDC準拠）:
 * 1. 署名検証（RSA）- JWKSから自動取得
 * 2. Issuer（iss）検証
 * 3. Audience（aud）検証
 * 4. 有効期限（exp）検証
 */
@Service
@Slf4j
public class EntraIdJwtValidator {

    private final String clientId;
    private final String issuer;
    private final String jwksUri;
    private final boolean stubEnabled;
    
    private final JwtService jwtService;

    /**
     * コンストラクタ
     */
    public EntraIdJwtValidator(
            @Value("${entra.tenant-id}") String tenantId,
            @Value("${entra.client-id}") String clientId,
            @Value("${entra.issuer}") String issuer,
            @Value("${entra.jwks-uri}") String jwksUri,
            @Value("${stub.enabled}") boolean stubEnabled,
            JwtService jwtService) {
        
        this.clientId = clientId;
        this.issuer = issuer;
        this.jwksUri = jwksUri;
        this.stubEnabled = stubEnabled;
        this.jwtService = jwtService;
        
        log.info("EntraIdJwtValidator 初期化完了: stub={}, issuer={}", stubEnabled, issuer);
    }

    /**
     * Entra ID JWTを検証
     */
    public Claims validateEntraIdToken(String token) {
        log.debug("Entra ID JWT検証開始: stub={}", stubEnabled);
        
        if (stubEnabled) {
            return jwtService.validateEntraJwt(token);
        }
        
        return validateProductionJwt(token);
    }

    /**
     * 本番環境用JWT検証（Nimbus-JWT使用）
     */
    private Claims validateProductionJwt(String token) {
        try {
            // JWTプロセッサを作成
            DefaultJWTProcessor<SecurityContext> jwtProcessor = createJwtProcessor();
            
            // JWTを処理してclaimsを取得
            JWTClaimsSet claimsSet = jwtProcessor.process(token, null);
            
            // 手動で Issuer と Audience を検証
            validateClaims(claimsSet);
            
            log.info("Entra ID JWT検証成功: sub={}, email={}", 
                    claimsSet.getSubject(), claimsSet.getStringClaim("email"));
            
            // Nimbus claims → JJWT claims に変換
            return convertToJwtClaims(claimsSet);
            
        } catch (Exception e) {
            // Nimbus-JWTの例外をチェック
            String message = e != null ? e.getMessage() : "";
            if (message.contains("expired") || message.contains("Expiry")) {
                log.warn("Entra ID JWT有効期限切れ: {}", message);
                throw AuthException.entraJwtExpired();
            }
            
            log.warn("Entra ID JWT検証失敗: {}", message);
            throw AuthException.entraTokenInvalid();
        }
    }

    /**
     * Claimsを手動検証（Issuer と Audience）
     */
    private void validateClaims(JWTClaimsSet claimsSet) {
        // Issuer 検証
        String actualIssuer = claimsSet.getIssuer();
        if (!issuer.equals(actualIssuer)) {
            log.warn("Issuer不一致: expected={}, actual={}", issuer, actualIssuer);
            throw AuthException.entraTokenInvalid();
        }
        
        // Audience 検証
        List<String> audiences = claimsSet.getAudience();
        if (audiences == null || !audiences.contains(clientId)) {
            log.warn("Audience不一致: expected={}, actual={}", clientId, audiences);
            throw AuthException.entraTokenInvalid();
        }
    }

    /**
     * JWTプロセッサを生成
     */
    private DefaultJWTProcessor<SecurityContext> createJwtProcessor() {
        try {
            // RemoteJWKSet: JWKSUriから自動的に鍵を取得
            URL jwksUrl = new URL(jwksUri);
            
            DefaultJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            
            // 鍵セレクタ: RS256方式进行签名验证
            JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                    JWSAlgorithm.RS256, 
                    new com.nimbusds.jose.jwk.source.RemoteJWKSet<>(jwksUrl)
            );
            
            processor.setJWSKeySelector(keySelector);
            
            log.info("JWTプロセッサ初期化完了: jwksUri={}", jwksUri);
            
            return processor;
            
        } catch (MalformedURLException e) {
            log.error("JWKS URIが無効: {}", jwksUri, e);
            throw new IllegalStateException("JWKS URIの初期化に失敗しました", e);
        }
    }

    /**
     * Nimbus JWTClaimsSet → JJWT Claims に変換
     */
    private Claims convertToJwtClaims(JWTClaimsSet nimbusClaims) {
        // Nimbus claims を Map に変換
        Map<String, Object> claimsMap = new HashMap<>();
        claimsMap.put("sub", nimbusClaims.getSubject());
        claimsMap.put("iss", nimbusClaims.getIssuer());
        
        // すべてのクレームを取得してマージ
        @SuppressWarnings("unchecked")
        Map<String, Object> allClaims = nimbusClaims.toJSONObject();
        if (allClaims != null) {
            claimsMap.putAll(allClaims);
        }
        
        // JJWTのビルダーパターンを使ってClaimsを作成
        return Jwts.claims().add(claimsMap).build();
    }
}