import { Injectable, inject } from '@angular/core';
import { CanActivate, CanActivateChild, CanActivateFn, CanActivateChildFn, Router, ActivatedRouteSnapshot, RouterStateSnapshot } from '@angular/router';
import { TokenService } from '../services/token.service';
import { TokenRefreshService } from '../services/token-refresh.service';
import { firstValueFrom } from 'rxjs';

/**
 * 認証ガード（関数型 + クラス委譲パターン）
 * 
 * ユーザーが認証されているかをチェック。
 * JWTが無効な場合はEntra ID認証へリダイレクト。
 * 
 * @returns
 * - `true`: 認証成功、アクセス許可（または認証不要パス）
 * - `false`: 認証失敗、Entra ID認証へリダイレクト済み（戻り値は形式的なもの）
 * 
 * @example
 * // canActivate用（親ルート・通常ルート）
 * { path: 'dashboard', component: DashboardComponent, canActivate: [AuthGuard] }
 * 
 * @example
 * // canActivateChild用（子ルート用）
 * { 
 *   path: 'settings',
 *   canActivateChild: [AuthChildGuard],
 *   children: [...]
 * }
 */

export const AuthGuard: CanActivateFn = (
  route: ActivatedRouteSnapshot, 
  state: RouterStateSnapshot
) => {
  return inject(AuthGuardT).canActivate(route, state);
};

/**
 * 子ルート用認証ガード（関数型）
 * 
 * canActivateChild として使用。
 * 親ルートに設定することで、子ルート全体に認証を適用できる。
 */
export const AuthChildGuard: CanActivateChildFn = (
  childRoute: ActivatedRouteSnapshot, 
  state: RouterStateSnapshot
) => {
  return inject(AuthGuardT).canActivateChild(childRoute, state);
};

/**
 * 認証ガードクラス（委譲先）
 * 
 * 実際の認証ロジックを実装。
 * Angular DI コンテナに登録され、関数型ガードから委譲される。
 * CanActivate と CanActivateChild の両方を実装。
 */
@Injectable()
export class AuthGuardT implements CanActivate, CanActivateChild {
  constructor(
    private tokenService: TokenService,
    private tokenRefreshService: TokenRefreshService,
    private router: Router
  ) {}

  /**
   * ルートアクティベーションの可否を判定（親ルート・通常ルート用）
   * 
   * @param route - アクティブ化されたルートのスナップショット
   * @param state - ルーターの現在の状態
   * @returns `true`（アクセス許可）または `false`（認証失敗、既にリダイレクト済み）
   * 
   * @remarks
   * MSALのloginRedirect()は内部でwindow.location.hrefを実行するため、
   * return false は到達しないデッドコード（Angularの型契約を満たすための形式）。
   */
  async canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Promise<boolean> {
    return this.checkAuth(state);
  }

  /**
   * 子ルートアクティベーションの可否を判定（子ルート用）
   * 
   * @param childRoute - 子ルートのスナップショット
   * @param state - ルーターの現在の状態
   * @returns `true`（アクセス許可）または `false`（認証失敗、既にリダイレクト済み）
   * 
   * @remarks
   * canActivate と同一の認証ロジックを使用。
   * MSALのloginRedirect()は内部でwindow.location.hrefを実行するため、
   * return false は到達しないデッドコード（Angularの型契約を満たすための形式）。
   */
  async canActivateChild(
    childRoute: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Promise<boolean> {
    return this.checkAuth(state);
  }

  /**
   * 共通認証チェックロジック
   * 
   * @param state - ルーターの現在の状態
   * @returns `true`（アクセス許可）または `false`（認証失敗、既にリダイレクト済み）
   */
  private async checkAuth(state: RouterStateSnapshot): Promise<boolean> {
    // JWT有効ならアクセス許可
    console.log('[AuthGuard] checkAuth 開始 - url:', state.url);
    
    // callbackページは認証チェックをスキップ
    if (state.url.includes('/callback')) {
      console.log('[AuthGuard] callbackページのため認証チェックスキップ');
      return true;
    }
    
    const isValid = this.tokenService.isTokenValid();
    console.log('[AuthGuard] checkAuth:', state.url, 'tokenValid:', isValid);
    if (isValid) {
      return true;
    }

    console.warn('[AuthGuard] JWT無効、サイレント更新試行');

    // JWT無効 → TokenRefreshService でサイレント更新
    try {
      const newToken = await firstValueFrom(
        this.tokenRefreshService.performSilentRefresh()
      );

      if (newToken) {
        console.log('[AuthGuard] サイレント更新成功、アクセス許可');
        return true;
      }
      
      console.warn('[AuthGuard] サイレント更新失敗（nullトークン）');
    } catch (error) {
      console.warn('[AuthGuard] サイレント更新失敗:', error);
    }

    // サイレント更新失敗 → ログインページへリダイレクト
    console.warn('[AuthGuard] 認証失敗、ログインページへリダイレクト');
    
    // 注意: ログイン成功後も元のURLには戻らない
    // 理由: ページロードでAngularコンポーネントのデータが失われるため
    
    // 再ログインが必要な旨をメッセージとして渡す
    this.router.navigate(['/login'], {
      queryParams: { 
        reason: 'session_expired',
        message: 'セッションの有効期限が切れました。再度ログインしてください。'
      }
    });
    
    // このreturnは実行されない（既にページ全体リダイレクトが発生済み）
    // AngularのCanActivateインターフェース契約を満たすための形式
    return false;
  }
}
