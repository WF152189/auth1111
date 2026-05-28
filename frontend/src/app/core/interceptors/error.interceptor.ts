import { HttpInterceptorFn, HttpErrorResponse } from '@angular/common/http';
import { inject } from '@angular/core';
import { Router } from '@angular/router';
import { catchError, switchMap, throwError, Observable, EMPTY } from 'rxjs';
import { TokenService } from '../services/token.service';
import { TokenRefreshService } from '../services/token-refresh.service';

/**
 * エラー処理interceptor（キュー方式）
 * 
 * 責務:
 * - 業務API（/auth/ と /stub/ を除いたURL）のエラーを処理
 * - 401: サイレント更新 → リトライ
 * - 403: 権限エラーページへ
 * 
 * 設計原則:
 * - 認証API（/auth/*）のエラーは直接透過（ここでは処理しない）
 * - 認証エラーは auth.service.ts で個別処理
 * 
 * キュー方式:
 * - 同時リクエストが発生しても、1回のサイレント更新で全て処理
 * - BehaviorSubject で更新状態を共有
 */
export const errorInterceptor: HttpInterceptorFn = (req, next): Observable<any> => {
  const router = inject(Router);
  const tokenService = inject(TokenService);
  const tokenRefreshService = inject(TokenRefreshService);

  // 認証系・スタブ系APIのエラーは処理しない（直接透過）
  const skipUrls = ['/auth/', '/stub/'];
  const shouldSkip = skipUrls.some(url => req.url.includes(url));

  if (shouldSkip) {
    return next(req);
  }

  // 業務APIのエラーを処理
  return next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 401) {
        // 業務JWT無効 → サイレント更新
        console.warn('[errorInterceptor] 401エラー: サイレント更新開始');
        return handle401Error(req, next, tokenRefreshService, tokenService, router);
        
      } else if (error.status === 403) {
        // 権限エラー → forbidden ページ
        console.warn('[errorInterceptor] 403エラー: 権限なし');
        router.navigate(['/error/forbidden']);
        // エラーを送出せず、EMPTY を返す
        return EMPTY;
      }

      // その他のエラーはそのまま伝播
      return throwError(() => error);
    })
  );
};

/**
 * 401エラー処理（キュー方式）
 * 
 * フロー:
 * 1. TokenRefreshService でサイレント更新
 * 2. 成功したら新JWTでリクエスト再試行
 * 3. 失敗したらログインページへ
 */
function handle401Error(
  req: any,
  next: any,
  tokenRefreshService: TokenRefreshService,
  tokenService: TokenService,
  router: Router
) {
  return tokenRefreshService.performSilentRefresh().pipe(
    switchMap((newToken: string | null) => {
      if (!newToken) {
        // 更新失敗 → ログインページへ
        console.warn('[errorInterceptor] サイレント更新失敗、ログインページへリダイレクト');
        redirectToLogin(router);
        // エラーを送出せず、EMPTY を返す（コンポーネントへのエラー伝播を防止）
        return EMPTY;
      }

      // 新JWTでリクエスト再試行
      console.log('[errorInterceptor] トークン更新成功、リトライ');
      const retryReq = req.clone({
        setHeaders: { Authorization: `Bearer ${newToken}` }
      });
      return next(retryReq);
    })
  );
}

/**
 * ログインページへリダイレクト
 */
function redirectToLogin(router: Router) {
  router.navigate(['/login'], {
    queryParams: {
      reason: 'session_expired',
      message: 'セッションの有効期限が切れました。再度ログインしてください。'
    }
  });
}
