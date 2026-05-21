import { Component } from '@angular/core';
import { CommonModule } from '@angular/common';
import { AuthService } from '../core/services/auth.service';
import { TokenService } from '../core/services/token.service';
import { Router, ActivatedRoute } from '@angular/router';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [CommonModule],
  template: `
    <div class="login-container">
      <div class="login-card">
        <h1>🔐 認証・認可システム</h1>
        
        <!-- セッション期限切れメッセージ -->
        <div *ngIf="sessionExpiredMessage" class="alert alert-warning">
          {{ sessionExpiredMessage }}
        </div>
        
        <p>業務システムへアクセスするにはログインが必要です。</p>
        <button class="login-btn" (click)="onLogin()">
          ログイン
        </button>
        <p class="info">※ スタブモード: テストユーザーを選択してログインできます</p>
      </div>
    </div>
  `,
  styles: [`
    .login-container {
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh; background: #f0f2f5;
    }
    .login-card {
      background: #fff; padding: 48px; border-radius: 12px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.1); text-align: center; max-width: 450px;
    }
    h1 { color: #1a1a2e; margin-bottom: 16px; }
    p { color: #666; margin-bottom: 24px; }
    .alert {
      padding: 12px 16px; border-radius: 6px; margin-bottom: 20px;
      font-size: 14px; text-align: left;
    }
    .alert-warning {
      background: #fff3cd; border: 1px solid #ffc107; color: #856404;
    }
    .login-btn {
      background: #0078d4; color: #fff; border: none; padding: 14px 32px;
      border-radius: 6px; font-size: 16px; cursor: pointer; width: 100%;
    }
    .login-btn:hover { background: #005a9e; }
    .info { font-size: 12px; color: #999; margin-top: 24px; }
  `]
})
export class LoginComponent {
  sessionExpiredMessage: string | null = null;

  constructor(
    private authService: AuthService,
    private tokenService: TokenService,
    private router: Router,
    private route: ActivatedRoute
  ) {}

  ngOnInit() {
    // 既にJWT有効ならダッシュボードへ
    if (this.tokenService.isTokenValid()) {
      this.router.navigate(['/dashboard']);
      return;
    }

    // クエリパラメータからセッション期限切れメッセージを取得
    this.route.queryParams.subscribe(params => {
      if (params['reason'] === 'session_expired') {
        this.sessionExpiredMessage = params['message'] || 'セッションの有効期限が切れました。再度ログインしてください。';
      }
    });
  }

  onLogin() {
    this.authService.login();
  }
}
