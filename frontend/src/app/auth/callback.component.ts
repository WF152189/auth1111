import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../core/services/auth.service';
import { CommonModule } from '@angular/common';

@Component({
    selector: 'app-callback',
    imports: [CommonModule],
    template: `
    <div class="callback-container">
      <div class="callback-card">
        <div *ngIf="!error" class="loading">
          <p>認証処理中...</p>
          <div class="spinner"></div>
        </div>
        <div *ngIf="error" class="error">
          <h2>⚠️ 認証エラー</h2>
          <p>{{ error }}</p>
          <p *ngIf="errorReason" class="error-detail">エラーコード: {{ errorReason }}</p>
          <button (click)="goToLogin()">ログイン画面に戻る</button>
        </div>
      </div>
    </div>
  `,
    styles: [`
    .callback-container {
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh; background: #f0f2f5;
    }
    .callback-card {
      background: #fff; padding: 48px; border-radius: 12px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center;
    }
    .spinner {
      border: 4px solid #f3f3f3; border-top: 4px solid #0078d4;
      border-radius: 50%; width: 40px; height: 40px;
      animation: spin 1s linear infinite; margin: 20px auto;
    }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    .error h2 { color: #d32f2f; }
    .error-detail { 
      color: #999; 
      font-size: 12px; 
      margin-top: 8px;
      font-family: monospace;
    }
    button {
      background: #0078d4; color: #fff; border: none; padding: 12px 24px;
      border-radius: 6px; cursor: pointer; margin-top: 16px;
    }
  `]
})
export class CallbackComponent implements OnInit {
  error: string | null = null;
  errorReason: string | null = null;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private authService: AuthService
  ) {}

  async ngOnInit() {
    console.log('[CallbackComponent] ngOnInit開始、URL:', window.location.href);
    
    try {
      // MSALパターン: パラメータはMSALが自動処理
      // handleCallback()内部でhandleRedirectPromise()が認可コードを検出
      console.log('[CallbackComponent] handleCallback() 呼び出し');
      const success = await this.authService.handleCallback();
      console.log('[CallbackComponent] handleCallback結果:', success);
      
      if (success) {
        // 認証成功 → 常にダッシュボードへ
        // 注意: redirect_url は使用しない
        // 理由: ページロードでAngularコンポーネントのデータが失われるため
        console.log('[CallbackComponent] ダッシュボードへ遷移');
        this.router.navigate(['/dashboard']);
      } else {
        // エラー理由を取得して表示
        this.errorReason = sessionStorage.getItem('auth_error_reason');
        
        if (this.errorReason) {
          this.error = this.getErrorMessage(this.errorReason);
          console.error('[CallbackComponent] エラー表示:', this.error);
        } else {
          this.error = '認証処理に失敗しました。もう一度お試しください。';
          console.error('[CallbackComponent] 認証失敗（詳細なし）');
        }
      }
    } catch (error) {
      console.error('[CallbackComponent] 予期せぬエラー:', error);
      this.error = '認証処理中にエラーが発生しました。';
    }
  }

  /**
   * エラーコードに応じてメッセージを返す
   */
  private getErrorMessage(code: string): string {
    switch (code) {
      case 'ENTRA_JWT_INVALID':
        return 'Entra IDトークンの署名検証に失敗しました。再度ログインしてください。';
      case 'ENTRA_JWT_EXPIRED':
        return 'Entra IDトークンの有効期限が切れています。再度ログインしてください。';
      case 'USER_NOT_FOUND':
        return 'ユーザーが見つかりません。管理者に問い合わせてください。';
      default:
        return '認証処理に失敗しました。もう一度お試しください。';
    }
  }

  goToLogin() {
    this.router.navigate(['/login']);
  }
}
