import { Injectable, inject } from '@angular/core';
import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Router } from '@angular/router';
import { TokenService } from './token.service';
import { MsalService, MsalRedirectRequest } from './msal.service';
import { environment } from '../../../environments/environment';
import { firstValueFrom } from 'rxjs';

/**
 * 認証エラー種別
 */
export type AuthErrorCode = 
  | 'ENTRA_TOKEN_INVALID'    // Entra JWT検証失敗（success=false）
  | 'ENTRA_JWT_EXPIRED'      // Entra JWT期限切れ
  | 'USER_NOT_FOUND'         // ユーザー未登録
  | 'INTERNAL_AUTH_FAILED'   // 内部認証失敗
  | 'INTERNAL_AUTH_DENIED'   // 内部認証拒否
  | 'SERVER_ERROR'           // サーバーエラー
  | 'UNKNOWN';               // その他

/**
 * 認証サービス - MSAL.js使用パターン
 * 
 * フロー:
 * 1. MSAL.jsでログインリダイレクト
 * 2. MSAL.jsで認可コード受信・トークン取得
 * 3. バックエンドAPIで業務JWT取得
 * 
 * エラー処理設計:
 * - すべてHTTP 200で返す
 * - 成功: { success: true, userId, email, ... }
 * - 失敗: { success: false, message: "..." }
 */
@Injectable({ providedIn: 'root' })
export class AuthService {
  private msalService = inject(MsalService);
  private http = inject(HttpClient);
  private router = inject(Router);
  private tokenService = inject(TokenService);

  // sessionStorage keys
  private readonly RETRY_KEY = 'auth_callback_retry';
  private readonly ENTRA_JWT_KEY = 'entra_jwt';
  private readonly MAX_RETRY = 1;

  /**
   * ログイン開始
   */
  login(): void {
    const request: MsalRedirectRequest = {
      scopes: ['openid', 'profile', 'email'],
      prompt: 'select_account'
    };

    this.msalService.loginRedirect(request);
  }

  /**
   * コールバック処理: MSALトークン取得 → 業務JWT取得
   * 
   * フロー:
   * 1. handleRedirectPromise() でEntra JWT取得（初回のみ）
   * 2. Entra JWTをsessionStorageに保存
   * 3. POST /auth/verify で業務JWT取得
   * 4. POST /auth/validate でsub検証
   * 
   * リトライ設計:
   * - リトライ時は保存されたEntra JWTを使用（handleRedirectPromise()不要）
   * - 無限ループ防止のため、最大1回リトライ
   */
  async handleCallback(): Promise<boolean> {
    const retryKey = this.RETRY_KEY;
    const entraJwtKey = this.ENTRA_JWT_KEY;

    try {
      // リトライカウンター確認
      const retryCount = parseInt(sessionStorage.getItem(retryKey) || '0', 10);
      
      // Entra JWT取得
      let entraJwt: string;
      
      if (retryCount === 0) {
        // 【初回】handleRedirectPromise() を使用
        console.log('[handleCallback] 初回実行');
        const msalResult = await this.msalService.handleRedirectPromise();
        
        if (!msalResult) {
          console.error('[handleCallback] MSAL result is null');
          return false;
        }
        
        entraJwt = msalResult.idToken;
        sessionStorage.setItem(entraJwtKey, entraJwt);
        console.log('[handleCallback] Entra JWT保存完了');
      } else {
        // 【リトライ】保存された Entra JWT を使用
        console.log('[handleCallback] リトライ実行');
        const cachedJwt = sessionStorage.getItem(entraJwtKey);
        
        if (!cachedJwt) {
          console.error('[handleCallback] 保存されたEntra JWTがない');
          this.cleanup();
          this.login();
          return false;
        }
        
        entraJwt = cachedJwt;
        console.log('[handleCallback] 保存されたEntra JWTを使用');
      }

      // 共通認証フロー実行
      return await this.runAuthFlow(entraJwt);

    } catch (err: any) {
      console.error('[handleCallback] エラー発生:', err);
      this.cleanup();
      return false;
    }
  }

  /**
   * サイレント更新用: Entra JWTを直接受け取り業務JWTを更新
   * 
   * フロー:
   * 1. acquireTokenSilent() で取得したEntra JWTを使用
   * 2. POST /auth/verify で業務JWT取得
   * 3. POST /auth/validate でsub検証
   * 
   * リトライ設計:
   * - handleCallback() と同一のリトライロジック
   * - 最大1回リトライ
   */
  async handleCallbackWithEntraJwt(entraJwt: string): Promise<boolean> {
    try {
      console.log('[handleCallbackWithEntraJwt] サイレント更新開始');
      
      // 共通認証フロー実行
      return await this.runAuthFlow(entraJwt);

    } catch (err: any) {
      console.error('[handleCallbackWithEntraJwt] エラー発生:', err);
      this.cleanup();
      return false;
    }
  }

  /**
   * 共通認証フロー（verify → validate）
   * 
   * @param entraJwt - Entra ID JWT
   * @returns 認証成否
   */
  private async runAuthFlow(entraJwt: string): Promise<boolean> {
    // Step 1: /auth/verify 呼び出し
    console.log('[runAuthFlow] /auth/verify呼び出し開始');
    const verifyResult = await this.callVerifyApi(entraJwt);
    
    if (!verifyResult.success) {
      // Entra検証失敗（message !== SERVER_ERROR && message !== Tokenなし）→ 終了
      if (verifyResult.message !== 'SERVER_ERROR' && verifyResult.message !== 'Tokenなし') {
        console.warn('[runAuthFlow] Entra検証失敗（終了）:', verifyResult.message);
        this.cleanup();
        return false;
      }
      
      // サーバーエラー or Tokenなし → リトライ
      console.warn('[runAuthFlow] /auth/verify失敗（リトライ）:', verifyResult.message);
      return this.retryAuthFlow(() => this.runAuthFlow(entraJwt));
    }

    // Step 2: /auth/validate 呼び出し（userIdを渡す）
    console.log('[runAuthFlow] /auth/validate呼び出し開始');
    const validateResult = await this.callValidateApi(verifyResult.userId!);
    
    if (validateResult === 'success') {
      console.log('[runAuthFlow] 全認証フロー完了: 成功');
      this.cleanup();
      return true;
    } else if (validateResult === 'retry') {
      // 401 or 5xx → リトライ
      console.warn('[runAuthFlow] /auth/validate失敗（リトライ）');
      return this.retryAuthFlow(() => this.runAuthFlow(entraJwt));
    } else {
      // sub検証失敗 or その他エラー
      console.warn('[runAuthFlow] 認証フロー失敗');
      this.cleanup();
      return false;
    }
  }

  /**
   * リトライ実行
   * 
   * @param operation - 再実行する操作
   * @returns 操作結果
   */
  private async retryAuthFlow(operation: () => Promise<boolean>): Promise<boolean> {
    const retryKey = this.RETRY_KEY;
    const retryCount = parseInt(sessionStorage.getItem(retryKey) || '0', 10);
    
    if (retryCount >= this.MAX_RETRY) {
      console.error('[retryAuthFlow] リトライ上限到達');
      this.cleanup();
      return false;
    }
    
    // リトライカウンター増分
    sessionStorage.setItem(retryKey, String(retryCount + 1));
    console.log('[retryAuthFlow] リトライ実行:', retryCount + 1, '/', this.MAX_RETRY);
    
    // 再実行
    return operation();
  }

  /**
   * /auth/verify API呼び出し
   */
  private async callVerifyApi(entraJwt: string): Promise<{
    success: boolean;
    message?: string;
    userId?: string;
  }> {
    try {
      // Authorization headerからトークンを取得するために observe: 'response' を使用
      const response = await firstValueFrom(
        this.http.post<any>(`${environment.apiBaseUrl}/auth/verify`, {}, {
          headers: { 'Authorization': `Bearer ${entraJwt}` },
          withCredentials: true,
          observe: 'response'  // header-access用
        })
      );

      // success フィールドで成否を判定
      if (response && response.body && response.body.success) {
        // 業務JWTをheaderから抽出して保存
        const authHeader = response.headers.get('Authorization');
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.substring(7);
          this.tokenService.saveToken(token);
          console.log('[callVerifyApi] 業務JWT保存完了');
        } else {
          console.warn('[callVerifyApi] Authorization headerなし');
          return { success: false, message: 'Tokenなし' };
        }
        
        console.log('[callVerifyApi] /auth/verify成功');
        return { 
          success: true,
          userId: response.body.userId
        };
      } else {
        // 失敗
        console.warn('[callVerifyApi] /auth/verify失敗:', response?.body?.message);
        return { success: false, message: response?.body?.message };
      }

    } catch (error) {
      const httpError = error as HttpErrorResponse;
      
      // ネットワークエラー or 5xx
      if (httpError.status === 0 || httpError.status >= 500) {
        console.error('[callVerifyApi] サーバーエラー or 通信エラー:', httpError.status);
        return { success: false, message: 'SERVER_ERROR' };
      }
      
      // その他エラー
      console.error('[callVerifyApi] 予期せぬエラー:', httpError);
      return { success: false, message: 'UNKNOWN' };
    }
  }

  /**
   * /auth/validate API呼び出し
   * @param userId - ユーザーID（Entra sub）
   */
  private async callValidateApi(userId: string): Promise<'success' | 'fail' | 'retry'> {
    try {
      const response = await firstValueFrom(
        this.http.post<any>(`${environment.apiBaseUrl}/auth/validate`, { userId }, {
          withCredentials: true
        })
      );

      // success フィールドで成否を判定
      if (response && response.success) {
        console.log('[callValidateApi] sub検証成功');
        return 'success';
      } else {
        console.warn('[callValidateApi] sub検証失敗:', response?.message);
        return 'fail';
      }

    } catch (error) {
      const httpError = error as HttpErrorResponse;
      
      // 業務JWT無効（401）→ リトライ
      if (httpError.status === 401) {
        console.warn('[callValidateApi] 業務JWT無効（401）→ リトライ');
        return 'retry';
      }
      
      // サーバーエラー → リトライ
      if (httpError.status >= 500) {
        console.warn('[callValidateApi] サーバーエラー → リトライ');
        return 'retry';
      }
      
      // その他エラー → 終了
      console.error('[callValidateApi] 予期せぬエラー:', httpError);
      return 'fail';
    }
  }

  /**
   * sessionStorageのクリーンアップ
   */
  private cleanup(): void {
    sessionStorage.removeItem(this.RETRY_KEY);
    sessionStorage.removeItem(this.ENTRA_JWT_KEY);
  }

  /**
   * ログアウト
   */
  async logout(): Promise<void> {
    try {
      await firstValueFrom(
        this.http.post(`${environment.apiBaseUrl}/auth/logout`, {}, {
          withCredentials: true
        })
      ).catch(() => {});
    } catch (error) {
      console.error('ログアウトエラー:', error);
    }

    this.cleanup();
    this.msalService.logoutRedirect();
    this.tokenService.removeToken();
    this.router.navigate(['/logout']);
  }

  /**
   * MSALアカウント情報取得（ユーティリティ）
   */
  getAccount() {
    return this.msalService.getActiveAccount();
  }
}