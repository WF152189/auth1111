import { Injectable, InjectionToken, Inject, inject } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { IMsalService, MsalAuthenticationResult, MsalAccountInfo, MsalRedirectRequest, MsalSilentRequest, MSAL_INSTANCE_FACTORY, MsalInstanceFactory, defaultMsalFactory } from './msal.service';
import { environment } from '../../../environments/environment';
import { firstValueFrom } from 'rxjs';

/**
 * スタブ用MSALサービスのInjectionToken
 */
export const MSAL_STUB_DATA = new InjectionToken<MsalStubData>('MSAL_STUB_DATA');

/**
 * スタブ用MSALデータインターフェース
 */
export interface MsalStubData {
  /** ログイン成功時のユーザー名 */
  username?: string;
  /** ログイン成功時の表示名 */
  name?: string;
  /** テナントID */
  tenantId?: string;
  /** サブジェクト（ユーザーID） */
  sub?: string;
  /** メールアドレス */
  email?: string;
  /** ログインを失敗させるか */
  loginShouldFail?: boolean;
  /** サイレント更新を失敗させるか */
  silentRefreshShouldFail?: boolean;
}

/**
 * デフォルトスタブデータ
 */
export const DEFAULT_STUB_DATA: MsalStubData = {
  username: 'testuser@example.com',
  name: 'テストユーザー',
  tenantId: 'stub-tenant-id',
  sub: 'stub-user-sub-12345',
  email: 'testuser@example.com',
  loginShouldFail: false,
  silentRefreshShouldFail: false
};

/**
 * スタブ用MSALサービス
 * 
 * 実際のEntra IDとの通信を行わず、固定値を返す
 * 開発環境・テスト環境で使用
 */
@Injectable({ providedIn: 'root' })
export class MsalStubService implements IMsalService {
  private isAuthenticated = false;
  private stubData: MsalStubData;
  private http = inject(HttpClient);

  constructor(
    @Inject(MSAL_INSTANCE_FACTORY) msalFactory: MsalInstanceFactory,
    @Inject(MSAL_STUB_DATA) stubData?: MsalStubData
  ) {
    // スタブデータの設定（注入された値またはデフォルト値）
    this.stubData = { ...DEFAULT_STUB_DATA, ...stubData };
    
    console.log('[MsalStubService] スタブMSALサービス初期化:', this.stubData);
  }

  /**
   * ログインリダイレクト（スタブ）
   * 
   * バックエンドのユーザー選択画面にリダイレクト
   */
  async loginRedirect(request: MsalRedirectRequest): Promise<void> {
    console.log('[MsalStubService] loginRedirect 呼び出し:', request);
    console.log('[MsalStubService] スコープ:', request.scopes);
    console.log('[MsalStubService] prompt:', request.prompt);

    // ログイン失敗シナリオ
    if (this.stubData.loginShouldFail) {
      console.error('[MsalStubService] ログイン失敗（スタブ設定）');
      sessionStorage.setItem('auth_error_reason', 'LOGIN_FAILED');
      return;
    }

    // バックエンドのスタブユーザー選択画面にリダイレクト
    const apiBaseUrl = environment.apiBaseUrl || 'http://localhost:8080';
    const redirectUri = encodeURIComponent(environment.redirectUri);
    const state = 'stub-state-' + Date.now();
    
    // stateをsessionStorageに保存（コールバック時に検証用）
    sessionStorage.setItem('stub_state', state);
    
    const stubAuthUrl = `${apiBaseUrl}/stub/entra/authorize` +
      `?client_id=${environment.clientId}` +
      `&redirect_uri=${redirectUri}` +
      `&state=${state}` +
      `&scope=${request.scopes.join(' ')}`;
    
    console.log('[MsalStubService] スタブ認証画面にリダイレクト:', stubAuthUrl);
    
    // ユーザー選択画面にリダイレクト
    window.location.href = stubAuthUrl;
  }

  /**
   * リダイレクト後のコールバック処理（スタブ）
   * 
   * バックエンドの /stub/entra/token エンドポイントから JWT を取得
   */
  async handleRedirectPromise(): Promise<MsalAuthenticationResult | null> {
    console.log('[MsalStubService] handleRedirectPromise 開始');
    console.log('[MsalStubService] URL:', window.location.href);

    // URLから認可コードを抽出
    const urlParams = new URLSearchParams(window.location.hash.substring(1) || window.location.search.substring(1));
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    
    if (!code) {
      console.warn('[MsalStubService] 認可コードなし、nullを返却');
      return null;
    }

    // state検証（オプション）
    const savedState = sessionStorage.getItem('stub_state');
    if (savedState && state !== savedState) {
      console.warn('[MsalStubService] state不一致');
      return null;
    }

    try {
      // バックエンドの /stub/entra/token エンドポイントから JWT 取得
      const apiBaseUrl = environment.apiBaseUrl || 'http://localhost:8080';
      const tokenResponse: any = await firstValueFrom(
        this.http.post(`${apiBaseUrl}/stub/entra/token`, null, {
          params: {
            code: code,
            grant_type: 'authorization_code',
            redirect_uri: environment.redirectUri
          }
        })
      );

      console.log('[MsalStubService] トークン取得成功');

      // JWTからペイロードをデコード
      const idToken = tokenResponse.idToken;
      const payload = this.decodeJwtPayload(idToken);

      // アカウント情報生成
      const account: MsalAccountInfo = {
        homeAccountId: `${payload.sub}.${payload.tid}`,
        environment: 'stub.login.microsoftonline.com',
        tenantId: payload.tid || 'stub-tenant-id',
        username: payload.preferred_username || payload.email,
        name: payload.name || 'テストユーザー',
        idToken: idToken,
        idTokenClaims: payload
      };

      // 認証結果生成
      const result: MsalAuthenticationResult = {
        accessToken: tokenResponse.idToken, // スタブでは同じトークンを使用
        idToken: idToken,
        account: account,
        fromCache: false,
        expiresOn: new Date(payload.exp * 1000),
        tokenType: 'Bearer'
      };

      console.log('[MsalStubService] handleRedirectPromise 成功:', account.username);
      this.isAuthenticated = true;

      // トークンを保存（getActiveAccount用）
      localStorage.setItem('stub_current_token', idToken);

      return result;

    } catch (error) {
      console.error('[MsalStubService] トークン取得失敗:', error);
      throw error;
    }
  }

  /**
   * JWTのペイロードをデコード
   */
  private decodeJwtPayload(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT');
      }
      const payload = parts[1];
      const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
      return JSON.parse(decoded);
    } catch (error) {
      console.error('[MsalStubService] JWTデコード失敗:', error);
      return {};
    }
  }

  /**
   * アクティブなアカウント情報取得（スタブ）
   */
  getActiveAccount(): MsalAccountInfo | null {
    if (!this.isAuthenticated) {
      return null;
    }

    // 認証済みの場合は、現在のトークンから情報を取得
    // handleRedirectPromise で設定された情報を使用
    const token = localStorage.getItem('stub_current_token');
    if (token) {
      const payload = this.decodeJwtPayload(token);
      return {
        homeAccountId: `${payload.sub}.${payload.tid}`,
        environment: 'stub.login.microsoftonline.com',
        tenantId: payload.tid || 'stub-tenant-id',
        username: payload.preferred_username || payload.email,
        name: payload.name || 'テストユーザー',
        idToken: token,
        idTokenClaims: payload
      };
    }

    // フォールバック：スタブデータ
    return {
      homeAccountId: `${this.stubData.sub}.${this.stubData.tenantId}`,
      environment: 'stub.login.microsoftonline.com',
      tenantId: this.stubData.tenantId || 'stub-tenant-id',
      username: this.stubData.username || 'testuser@example.com',
      name: this.stubData.name || 'テストユーザー',
      idToken: '',
      idTokenClaims: {
        sub: this.stubData.sub,
        tid: this.stubData.tenantId,
        name: this.stubData.name,
        preferred_username: this.stubData.username,
        email: this.stubData.email
      }
    };
  }

  /**
   * ログアウトリダイレクト（スタブ）
   */
  async logoutRedirect(): Promise<void> {
    console.log('[MsalStubService] logoutRedirect 呼び出し');
    
    // 認証状態をリセット
    this.isAuthenticated = false;
    
    // 保存されたデータをクリア
    localStorage.removeItem('stub_current_token');
    sessionStorage.removeItem('stub_state');
    
    console.log('[MsalStubService] ログアウト完了（スタブ）');
  }

  /**
   * サイレントトークン更新（スタブ）
   */
  async acquireTokenSilent(request?: MsalSilentRequest): Promise<string | null> {
    console.log('[MsalStubService] acquireTokenSilent 呼び出し:', request);

    // 認証されていない場合はnull
    if (!this.isAuthenticated) {
      console.warn('[MsalStubService] 未認証のため、nullを返却');
      return null;
    }

    // サイレント更新失敗シナリオ
    if (this.stubData.silentRefreshShouldFail) {
      console.error('[MsalStubService] サイレント更新失敗（スタブ設定）');
      return null;
    }

    // 現在のIDトークンを返す
    const account = this.getActiveAccount();
    if (account && account.idToken) {
      console.log('[MsalStubService] サイレント更新成功（スタブ）');
      return account.idToken;
    }

    return null;
  }
}
