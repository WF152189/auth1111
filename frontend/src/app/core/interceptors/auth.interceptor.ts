import { HttpInterceptorFn } from '@angular/common/http';
import { inject } from '@angular/core';
import { TokenService } from '../services/token.service';

/**
 * 認証トークン付与interceptor
 * 
 * 責務:
 * - 業務API（/auth/ と /stub/ を除いたURL）にBearerトークンを付与
 * - 認証API (/auth/*) には、トークン付与しない（自己完結の検証フロー）
 * 
 * 设计原则:
 * - 认证相关的请求（/auth/*）不应该添加业务JWT
 * - 这些请求会直接调用 handleCallback() 进行处理
 */
export const authInterceptor: HttpInterceptorFn = (req, next) => {
  const tokenService = inject(TokenService);

  // 認証系・スタブ系APIにはBearerヘッダーを付与しない
  const skipUrls = ['/auth/', '/stub/'];
  const shouldSkip = skipUrls.some(url => req.url.includes(url));

  if (shouldSkip) {
    return next(req);
  }

  // 業務APIにはBearerトークンを付与
  const token = tokenService.getToken();
  if (token) {
    const authReq = req.clone({
      setHeaders: { Authorization: `Bearer ${token}` }
    });
    return next(authReq);
  }

  return next(req);
};