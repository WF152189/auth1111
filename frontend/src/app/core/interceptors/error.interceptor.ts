import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, throwError } from 'rxjs';
import { TokenService } from '../services/token.service';

/**
 * エラー処理interceptor
 * 
 * 責務:
 * - 業務API（/auth/ と /stub/ を除いたURL）のエラーを処理
 * - 401: ログアウトしてログインページへ
 * - 403: 権限エラーページへ
 * 
 * 设计原则:
 * - 认证API (/auth/*) のエラーは直接透传（不在这里处理）
 * - 认证错误由 auth.service.ts 单独处理
 */
export const errorInterceptor: HttpInterceptorFn = (req, next) => {
  const router = inject(Router);
  const tokenService = inject(TokenService);

  // 認証系・スタブ系APIのエラーは処理しない（直接透传）
  const skipUrls = ['/auth/', '/stub/'];
  const shouldSkip = skipUrls.some(url => req.url.includes(url));

  if (shouldSkip) {
    return next(req);
  }

  // 業務APIのエラーを処理
  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401) {
        // 業務JWT無効 → ログアウト
        console.warn('[errorInterceptor] 401エラー: ログアウト処理');
        tokenService.removeToken();
        router.navigate(['/login']);
        
      } else if (error.status === 403) {
        // 権限エラー → forbidden ページ
        console.warn('[errorInterceptor] 403エラー: 権限なし');
        router.navigate(['/error/forbidden']);
      }

      return throwError(() => error);
    })
  );
};