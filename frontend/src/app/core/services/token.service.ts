import { Injectable } from '@angular/core';

const JWT_KEY = 'business_jwt';

@Injectable({ providedIn: 'root' })
export class TokenService {

  /**
   * 業務JWTをLocalStorageに保存
   */
  saveToken(token: string): void {
    localStorage.setItem(JWT_KEY, token);
  }

  /**
   * 業務JWTをLocalStorageから取得
   */
  getToken(): string | null {
    return localStorage.getItem(JWT_KEY);
  }

  /**
   * 業務JWTをLocalStorageから削除
   */
  removeToken(): void {
    localStorage.removeItem(JWT_KEY);
  }

  /**
   * 業務JWTが有効かどうか（存在 かつ exp未超過）
   */
  isTokenValid(): boolean {
    
    const token = this.getToken();
    if (!token) return false;

    try {
      const payload = this.decodePayload(token);
      const exp = payload.exp * 1000; // sec → ms
      return Date.now() < exp;
    } catch {
      return false;
    }
  }

  /**
   * JWTペイロードをデコード
   */
  decodePayload(token: string): any {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid JWT');
    const payload = parts[1];
    const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    return JSON.parse(decoded);
  }

  /**
   * ペイロードから権限一覧を取得
   */
  getPermissions(): string[] {
    const token = this.getToken();
    if (!token) return [];
    try {
      return this.decodePayload(token).permissions || [];
    } catch {
      return [];
    }
  }

  /**
   * ペイロードからロール一覧を取得
   */
  getRoles(): string[] {
    const token = this.getToken();
    if (!token) return [];
    try {
      return this.decodePayload(token).roles || [];
    } catch {
      return [];
    }
  }

  /**
   * ペイロードからユーザー情報を取得
   */
  getUserInfo(): { userId: string; email: string; displayName: string } | null {
    const token = this.getToken();
    if (!token) return null;
    try {
      const payload = this.decodePayload(token);
      return {
        userId: payload.sub,
        email: payload.email,
        displayName: payload.display_name
      };
    } catch {
      return null;
    }
  }
}
