import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, from, take, switchMap } from 'rxjs';
import { MsalService } from './msal.service';
import { AuthService } from './auth.service';
import { TokenService } from './token.service';

/**
 * トークン更新サービス（キュー方式）
 * 
 * 責務:
 * - サイレントトークン更新の一元管理
 * - 同時リクエストのキューイング
 * - 更新状態の共有
 * 
 * 使用シーン:
 * - AuthGuard: JWT期限切れ時のサイレント更新
 * - errorInterceptor: 401エラー時のトークン更新
 * - コンポーネント: 必要に応じたトークン更新
 */
@Injectable({
  providedIn: 'root'
})
export class TokenRefreshService {
  private isRefreshing = false;
  private refreshTokenSubject = new BehaviorSubject<string | null>(null);

  constructor(
    private msalService: MsalService,
    private authService: AuthService,
    private tokenService: TokenService
  ) {}

  /**
   * サイレントトークン更新実行
   * 
   * フロー:
   * 1. 更新中の場合は完了を待機
   * 2. 新規更新なら acquireTokenSilent() → handleCallbackWithEntraJwt()
   * 3. 新JWTを返却
   * 
   * @returns 新JWT、またはnull（更新失敗）
   */
  performSilentRefresh(): Observable<string | null> {
    // 既に更新中の場合は待機
    if (this.isRefreshing) {
      console.log('[TokenRefreshService] 既にトークン更新中、待機');
      return this.refreshTokenSubject.pipe(
        take(1),
        switchMap((token) => {
          console.log('[TokenRefreshService] 更新完了、待機解除');
          return new Observable<string | null>(observer => observer.next(token));
        })
      );
    }

    // 新規更新処理
    this.isRefreshing = true;
    console.log('[TokenRefreshService] サイレント更新開始');

    return from(this.executeTokenRefresh()).pipe(
      switchMap((newToken) => {
        this.isRefreshing = false;
        console.log('[TokenRefreshService] 更新処理完了');
        return new Observable<string | null>(observer => observer.next(newToken));
      })
    );
  }

  /**
   * 実際のトークン更新処理
   */
  private async executeTokenRefresh(): Promise<string | null> {
    try {
      // Step 1: acquireTokenSilent() でEntra ID token取得
      const entraJwt = await this.msalService.acquireTokenSilent({
        scopes: ['openid', 'profile', 'email']
      });

      if (!entraJwt) {
        console.warn('[TokenRefreshService] acquireTokenSilent() 失敗');
        this.refreshTokenSubject.next(null);
        return null;
      }

      // Step 2: handleCallbackWithEntraJwt() で業務JWT更新
      const result = await this.authService.handleCallbackWithEntraJwt(entraJwt);

      if (!result) {
        console.warn('[TokenRefreshService] 業務JWT更新失敗');
        this.refreshTokenSubject.next(null);
        return null;
      }

      // Step 3: 新JWT取得
      const newToken = this.tokenService.getToken();
      
      if (!newToken) {
        console.error('[TokenRefreshService] 新JWTが見つからない');
        this.refreshTokenSubject.next(null);
        return null;
      }

      console.log('[TokenRefreshService] トークン更新成功');
      
      // 待機中のリクエストに通知
      this.refreshTokenSubject.next(newToken);
      
      return newToken;

    } catch (error) {
      console.error('[TokenRefreshService] サイレント更新エラー:', error);
      this.refreshTokenSubject.next(null);
      return null;
    }
  }
}
