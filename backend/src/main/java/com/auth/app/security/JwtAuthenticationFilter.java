package com.auth.app.security;

import com.auth.app.service.JwtService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain) throws ServletException, IOException {
        String authHeader = request.getHeader("Authorization");

        // Authorizationヘッダーがない場合
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("Authorizationヘッダーなしまたは形式不正");
            sendUnauthorizedError(response, "TOKEN_MISSING", "認証トークンが必要です。");
            return;
        }

        String token = authHeader.substring(7);
        
        try {
            Claims claims = jwtService.validateToken(token);
            String userId = claims.getSubject();

            // ロールと権限をGrantedAuthorityに変換
            List<SimpleGrantedAuthority> authorities = new ArrayList<>();

            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class);
            if (roles != null) {
                roles.stream()
                     .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                     .forEach(authorities::add);
            }

            @SuppressWarnings("unchecked")
            List<String> permissions = claims.get("permissions", List.class);
            if (permissions != null) {
                permissions.stream()
                           .map(SimpleGrantedAuthority::new)
                           .forEach(authorities::add);
            }

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(userId, null, authorities);
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.debug("JWT認証成功: userId={}, authorities={}", userId, authorities);
            
            // 認証成功の場合は次のフィルターへ
            filterChain.doFilter(request, response);
            
        } catch (ExpiredJwtException e) {
            log.warn("JWT期限切れ: {}", e.getMessage());
            sendUnauthorizedError(response, "JWT_EXPIRED", "認証トークンの有効期限が切れています。");
        } catch (JwtException e) {
            log.warn("JWT検証失敗: {}", e.getMessage());
            sendUnauthorizedError(response, "JWT_INVALID", "認証トークンが無効です。");
        }
    }

    /**
     * 401 Unauthorized エラーレスポンスを返す
     */
    private void sendUnauthorizedError(HttpServletResponse response, 
                                       String errorCode, 
                                       String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        String json = String.format(
            "{\"success\":false,\"code\":\"%s\",\"message\":\"%s\"}",
            errorCode,
            message
        );
        
        response.getWriter().write(json);
        response.getWriter().flush();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // /auth/validate は内部でJWT検証するため、フィルターでは除外
        // 他の /auth/* も除外（ログイン、verify など）
        return path.startsWith("/auth/") ||
               path.startsWith("/stub/") ||
               path.startsWith("/h2-console");
    }
}
