import { Injectable, inject } from '@angular/core';
import { CanActivate, CanActivateChild, CanActivateFn, CanActivateChildFn, ActivatedRouteSnapshot, RouterStateSnapshot, Router } from '@angular/router';
import { ScreenPermissionService } from '../services/screen-permission.service';
import { PermissionErrorService } from '../services/permission-error.service';

/**
 * 画面権限ガード（関数型 - ルート用）
 * 
 * ルート定義のdata['screenId']から画面IDを取得し、
 * ユーザーの画面アクセス権限をチェックする。
 * 
 * @returns
 * - `true`: アクセス許可、または画面ID未設定（デフォルト許可）
 * - `false`: アクセス拒否（画面遷移をブロック、エラーメッセージ表示）
 * 
 * @example
 * // canActivate用（親ルート・通常ルート）
 * { 
 *   path: 'business/data',
 *   component: SampleDataComponent,
 *   canActivate: [permissionGuard],
 *   data: { screenId: 'BUSINESS_DATA_SCREEN' }
 * }
 * 
 * @example
 * // canActivateChild用（子ルート用）
 * { 
 *   path: 'settings',
 *   canActivateChild: [permissionChildGuard],
 *   children: [...]
 * }
 */
export const permissionGuard: CanActivateFn = (
  route: ActivatedRouteSnapshot, 
  state: RouterStateSnapshot
) => {
  return inject(PermissionGuardT).canActivate(route, state);
};

/**
 * 子ルート用画面権限ガード（関数型）
 * 
 * canActivateChild として使用。
 * 親ルートに設定することで、子ルート全体に権限制御を適用できる。
 */
export const permissionChildGuard: CanActivateChildFn = (
  childRoute: ActivatedRouteSnapshot, 
  state: RouterStateSnapshot
) => {
  return inject(PermissionGuardT).canActivateChild(childRoute, state);
};

/**
 * 画面権限ガードクラス（委譲先）
 * 
 * 実際の権限チェックロジックを実装。
 * Angular DI コンテナに登録され、関数型ガードから委譲される。
 * CanActivate と CanActivateChild の両方を実装。
 */
@Injectable()
export class PermissionGuardT implements CanActivate, CanActivateChild {

  constructor(
    private screenPermissionService: ScreenPermissionService,
    private permissionErrorService: PermissionErrorService,
    private router: Router
  ) {}

  /**
   * ルートアクティベーションの可否を判定（親ルート・通常ルート用）
   * 
   * @param route - アクティブ化されたルートのスナップショット
   * @param state - ルーターの現在の状態
   * @returns `true`（アクセス許可）または `false`（アクセス拒否、エラーメッセージ表示）
   */
  async canActivate(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Promise<boolean> {
    console.log('[PermissionGuard] canActivate 開始 - 時刻:', Date.now());
    const result = await this.checkPermission(route, state);
    console.log('[PermissionGuard] canActivate 完了 - 時刻:', Date.now(), '結果:', result);
    return result;
  }

  /**
   * 子ルートアクティベーションの可否を判定（子ルート用）
   * 
   * @param childRoute - 子ルートのスナップショット
   * @param state - ルーターの現在の状態
   * @returns `true`（アクセス許可）または `false`（アクセス拒否、エラーメッセージ表示）
   */
  async canActivateChild(
    childRoute: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Promise<boolean> {
    return this.checkPermission(childRoute, state);
  }

  /**
   * 共通権限チェックロジック
   * 
   * @param route - ルートのスナップショット
   * @param state - ルーターの現在の状態（遷移元URLを含む）
   * @returns `true`（アクセス許可）または `false`（アクセス拒否、エラーメッセージ表示）
   */
  private async checkPermission(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Promise<boolean> {
    const screenId: string = route.data?.['screenId'];
    
    // 画面IDが設定されていない場合は許可（デフォルト）
    if (!screenId) {
      console.warn('PermissionGuard: 画面IDが設定されていません');
      return true;
    }
  
    // 画面権限をチェック
    const result = await this.screenPermissionService.checkScreenPermission(screenId);
    
    if (result.authorized) {
      // アクセス許可
      return true;
    }
  
    // アクセス拒否：エラー情報を保存して遷移元画面にリダイレクト
    console.warn('画面アクセスが拒否されました:', screenId, result.reason);
    
    // エラー情報をセッションに保存
    this.permissionErrorService.setPermissionError({
      screenId: screenId,
      reason: result.reason || 'この画面にアクセスする権限がありません。'
    });
    
    // 遷移元URLを取得（state.url）またはデフォルト
    const returnUrl = state.url || '/dashboard';
    console.log('[PermissionGuard] 遷移元URL:', returnUrl);
    
    // 遷移元画面に戻る（クエリパラメータでエラー理由を渡す）
    this.router.navigate([returnUrl], {
      queryParams: {
        error: 'permission_denied',
        message: result.reason || 'この画面にアクセスする権限がありません。'
      }
    });
    
    return false;
  }
}
