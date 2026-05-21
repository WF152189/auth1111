import { Injectable } from '@angular/core';
import { PublicClientApplication, Configuration, AuthenticationResult, RedirectRequest, SilentRequest, INavigationClient, NavigationOptions } from '@azure/msal-browser';
import { environment } from '../../../environments/environment';

/**
 * MSAL AccountInfo インターフェース
 */
export interface MsalAccountInfo {
  homeAccountId: string;
  environment: string;
  tenantId: string;
  username: string;
  name: string;
  idToken: string;
  idTokenClaims: any;
}

/**
 * MSAL AuthenticationResult インターフェース
 */
export interface MsalAuthenticationResult {
  accessToken: string;
  idToken: string;
  account: MsalAccountInfo | null;
  fromCache: boolean;
  expiresOn: Date | null;
  tokenType: string;
}

/**
 * MSAL RedirectRequest インターフェース
 */
export interface MsalRedirectRequest {
  scopes: string[];
  prompt?: string;
  state?: string;
}

/**
 * MSAL SilentRequest インターフェース
 */
export interface MsalSilentRequest {
  scopes: string[];
  account?: MsalAccountInfo;
}

/**
 * MSALサービスインターフェース
 * 
 * @azure/msal-browser の PublicClientApplication を使用
 */
export interface IMsalService {
  loginRedirect(request: MsalRedirectRequest): Promise<void>;
  handleRedirectPromise(): Promise<MsalAuthenticationResult | null>;
  getActiveAccount(): MsalAccountInfo | null;
  logoutRedirect(): Promise<void>;
}

/**
 * 本番環境用MSALサービス
 * 
 * 実際のAzure MSAL.jsライブラリを使用
 * シングルテナント構成
 */
@Injectable({ providedIn: 'root' })
export class MsalService implements IMsalService {
  private msalInstance: PublicClientApplication;

  constructor() {
    // カスタムナビゲーションクライアント（MSALの内部ナビゲーションを制御）
    const customNavigationClient: INavigationClient = {
      // 内部ナビゲーション（SPA内のページ遷移）
      async navigateInternal(url: string, options: NavigationOptions): Promise<boolean> {
        console.log('[MsalService] navigateInternal 呼び出し:', url);
        console.log('[MsalService] navigateInternal options:', options);
        // falseを返すと、MSALはページのリロードを試みない
        return false;
      },
      // 外部ナビゲーション（IDPへのリダイレクトなど）
      async navigateExternal(url: string, options: NavigationOptions): Promise<boolean> {
        console.log('[MsalService] navigateExternal 呼び出し:', url);
        console.log('[MsalService] navigateExternal options:', options);
        // 外部ナビゲーションは許可（ログインリダイレクトなど）
        window.location.href = url;
        return true;
      }
    };

    // MSAL設定
    // ※ as Configuration で型チェックを回避し、navigateToLoginRequestUrlを確実に設定
    const msalConfig = {
      auth: {
        clientId: environment.clientId,
        authority: environment.authority,  // シングルテナント
        redirectUri: environment.redirectUri,
        postLogoutRedirectUri: environment.redirectUri,
        navigateToLoginRequestUrl: false,  // 自動リダイレクト無効化（CallbackComponentで制御）
        prompt: 'select_account'  // 毎回アカウント選択を強制
      },
      cache: {
        cacheLocation: 'sessionStorage',  // セッションストレージ使用
        storeAuthStateInCookie: false  // Cookieに認証状態を保存しない（ページリロード防止）
      },
      system: {
        loggerOptions: {
          loggerCallback: (level: number, message: string, containsPii: boolean) => {
            if (containsPii) {
              return;
            }
            switch (level) {
              case 0: // Error
                console.error(message);
                return;
              case 1: // Warning
                console.warn(message);
                return;
              case 2: // Info
                console.info(message);
                return;
              case 3: // Verbose
                console.debug(message);
                return;
            }
          },
          piiLoggingEnabled: false,
          logLevel: 2 // Info
        },
        windowHashTimeout: 90000,  // ハッシュタイムアウト（ミリ秒）
        allowRedirectInIframe: false,  // iframeでのリダイレクトを許可しない
        navigationClient: customNavigationClient  // カスタムナビゲーションクライアントを設定
      }
    } as Configuration;

    console.log('[MsalService] navigateToLoginRequestUrl:', (msalConfig.auth as any).navigateToLoginRequestUrl);
    console.log('[MsalService] storeAuthStateInCookie:', (msalConfig.cache as any).storeAuthStateInCookie);
    console.log('[MsalService] customNavigationClient 設定済み');

    // MSALインスタンス生成
    this.msalInstance = new PublicClientApplication(msalConfig);
    
    // 初期化を実行（handleRedirectPromiseの前に完了している必要がある）
    this.msalInstance.initialize().then(() => {
      console.log('[MsalService] MSAL初期化完了');
    }).catch((error) => {
      console.error('[MsalService] MSAL初期化エラー:', error);
    });
  }

  /**
   * ログインリダイレクト
   * 
   * 本番環境: msalInstance.loginRedirect(request)
   */
  async loginRedirect(request: MsalRedirectRequest): Promise<void> {

    const loginRequest: RedirectRequest = {
      scopes: request.scopes || environment.scopes,
      prompt: request.prompt || 'select_account',
      state: request.state
    };

    this.msalInstance.loginRedirect(loginRequest);
  }

  /**
   * リダイレクト後のコールバック処理
   * 
   * 本番環境: msalInstance.handleRedirectPromise()
   */
  async handleRedirectPromise(): Promise<MsalAuthenticationResult | null> {
    console.log('[MsalService] handleRedirectPromise 開始, URL:', window.location.href);
    console.log('[MsalService] hash:', window.location.hash.substring(0, 50) + '...');
    
    try {
      // MSALの内部状態を確認
      console.log('[MsalService] MSALインスタンス状態確認');
      
      // MSALがURLを操作する前に、現在の状態を保存
      const currentHash = window.location.hash;
      const currentUrl = window.location.href;
      console.log('[MsalService] 現在のハッシュ:', currentHash.substring(0, 50) + '...');
      
      // 重要: MSAL v5のhandleRedirectPromiseは内部でURLを変更する可能性がある
      // そのため、処理が完了するまで待機
      console.log('[MsalService] handleRedirectPromise実行開始');
      const result: AuthenticationResult | null = await this.msalInstance.handleRedirectPromise();
      console.log('[MsalService] handleRedirectPromise実行完了');
  
      console.log('[MsalService] handleRedirectPromise 結果, result:', result ? 'あり' : 'null');
      console.log('[MsalService] 処理後のURL:', window.location.href);
      
      if (!result) {
        console.warn('[MsalService] handleRedirectPromise が null を返却（認可コードなし、または処理済み）');
        return null;
      }

      // アクティブアカウントを設定
      this.msalInstance.setActiveAccount(result.account);
      console.log('[MsalService] アクティブアカウント設定完了:', result.account?.username);

      // 結果をマッピング
      return this.mapAuthenticationResult(result);
    } catch (error: any) {
      console.error('[MsalService] handleRedirectPromise エラー:', error);
      console.error('[MsalService] エラーコード:', error?.errorCode);
      console.error('[MsalService] エラーメッセージ:', error?.message);
      
      // エラー情報を sessionStorage に保存（コールバックコンポーネントで表示用）
      if (error?.errorCode) {
        sessionStorage.setItem('auth_error_reason', error.errorCode);
      }
      
      throw error;
    }
  }

  /**
   * アクティブなアカウント情報取得
   * 
   * 本番環境: msalInstance.getActiveAccount()
   */
  getActiveAccount(): MsalAccountInfo | null {
    // getActiveAccountは同期的だが、初期化未完了時はnullを返す
    try {
      const account = this.msalInstance.getActiveAccount();
      if (!account) return null;
      return this.mapAccount(account);
    } catch {
      return null;
    }
  }

  /**
   * ログアウトリダイレクト
   * 
   * 本番環境: msalInstance.logoutRedirect()
   */
  async logoutRedirect(): Promise<void> {
    this.msalInstance.logoutRedirect({
      postLogoutRedirectUri: environment.redirectUri
    }).catch((error) => {
      console.error('MSAL logout error:', error);
    });
  }

  /**
   * サイレントトークン更新（必要に応じて使用）
   * 
   * @param request - サイレントリクエスト（スコープ指定）
   * @returns Entra ID token（idToken）または null
   */
  async acquireTokenSilent(request?: MsalSilentRequest): Promise<string | null> {
    const msalAccount = request?.account 
      ? this.mapToMsalAccount(request.account) 
      : this.msalInstance.getActiveAccount();
    
    if (!msalAccount) {
      console.warn('[acquireTokenSilent] アカウントが見つかりません');
      return null;
    }

    try {
      const silentRequest: SilentRequest = {
        scopes: request?.scopes || environment.scopes,
        account: msalAccount
      };

      const result = await this.msalInstance.acquireTokenSilent(silentRequest);
      console.log('[acquireTokenSilent] サイレント更新成功');
      return result.idToken;
    } catch (error) {
      console.warn('[acquireTokenSilent] サイレント更新失敗:', error);
      return null;
    }
  }

  /**
   * MsalAccountInfo を MSAL AccountInfo に変換
   */
  private mapToMsalAccount(account: MsalAccountInfo): any {
    return {
      homeAccountId: account.homeAccountId,
      environment: account.environment,
      tenantId: account.tenantId,
      username: account.username,
      name: account.name,
      idToken: account.idToken,
      idTokenClaims: account.idTokenClaims,
      localAccountId: account.idTokenClaims?.oid || ''  // MSAL v5 に必要なフィールド
    };
  }

  /**
   * AuthenticationResultをマッピング
   */
  private mapAuthenticationResult(result: AuthenticationResult): MsalAuthenticationResult {
    return {
      accessToken: result.accessToken,
      idToken: result.idToken,
      account: result.account ? this.mapAccount(result.account) : null,
      fromCache: result.fromCache,
      expiresOn: result.expiresOn,
      tokenType: result.tokenType
    };
  }

  /**
   * AccountInfoをマッピング
   */
  private mapAccount(account: any): MsalAccountInfo {
    return {
      homeAccountId: account.homeAccountId,
      environment: account.environment,
      tenantId: account.tenantId,
      username: account.username,
      name: account.name || '',
      idToken: account.idToken || '',
      idTokenClaims: account.idTokenClaims || {}
    };
  }
}
