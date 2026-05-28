import { Injectable } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { TokenService } from './token.service';
import { environment } from '../../../environments/environment';
import { firstValueFrom } from 'rxjs';

/**
 * 画面権限レスポンス
 */
export interface ScreenPermissionResult {
  authorized: boolean;
  message?: string;
  reason?: string;
}

/**
 * 画面権限チェックサービス
 * 
 * ユーザーが特定の画面にアクセスする権限を持っているかを確認する
 * バックエンドの画面権限APIと連携
 */
@Injectable({ providedIn: 'root' })
export class ScreenPermissionService {

  constructor(
    private http: HttpClient,
    private tokenService: TokenService
  ) {}

  /**
   * 画面権限をチェック
   * 
   * フロー:
   * 1. 現在のユーザーIDをJWTから取得
   * 2. バックエンドに画面権限をチェック依頼
   * 3. 結果を返却
   * 
   * @param screenId 画面ID（例: 'BUSINESS_DATA_SCREEN'）
   * @returns 権限チェック結果
   */
  async checkScreenPermission(screenId: string): Promise<ScreenPermissionResult> {
    try {
      // JWTからユーザーIDを取得
      // const userId = this.getUserIdFromJWT();
      // if (!userId) {
      //   console.error('ユーザーIDが取得できません');
      //   return {
      //     authorized: false,
      //     reason: 'ユーザー情報が無効です'
      //   };
      // }

      // バックエンドに権限チェックを依頼
      const result: ScreenPermissionResult = await firstValueFrom(
        this.http.post<ScreenPermissionResult>(
          `${environment.apiBaseUrl}/api/screens/permission/check`,
          {
            screenId: screenId
          },
          {
            withCredentials: true  // Cookie（RT）を自動送信
          }
        )
      );

      return result;

    } catch (error) {
      console.error('画面権限チェックでエラーが発生しました:', error);
      
      // エラー時は安全側に倒して失敗とする
      if (error instanceof HttpErrorResponse && error.status === 401) {
        // 認証エラー：セッション切れ
        return {
          authorized: false,
          reason: '認証セッションが切れています。再度ログインしてください。'
        };
      }
      
      return {
        authorized: false,
        reason: '画面権限チェックでエラーが発生しました'
      };
    }
  }

  /**
   * JWTからユーザーIDを取得
   */
  private getUserIdFromJWT(): string | null {
    const token = this.tokenService.getToken();
    if (!token) {
      return null;
    }

    try {
      // JWTのペイロードをデコード
      const payload = this.tokenService.decodePayload(token);
      return payload.sub || null;
    } catch (error) {
      console.error('JWTのデコードに失敗しました:', error);
      return null;
    }
  }
}
