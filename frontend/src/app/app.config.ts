import { ApplicationConfig, provideAppInitializer, inject } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient, withInterceptors } from '@angular/common/http';

import { routes } from './app.routes';
import { authInterceptor } from './core/interceptors/auth.interceptor';
import { errorInterceptor } from './core/interceptors/error.interceptor';
import { AuthGuardT } from './core/guards/auth.guard';
import { PermissionGuardT } from './core/guards/permission.guard';
import { MsalService, IMsalService, MSAL_SERVICE, MSAL_INSTANCE_FACTORY, defaultMsalFactory } from './core/services/msal.service';
import { MsalStubService, MSAL_STUB_DATA, MsalStubData, DEFAULT_STUB_DATA } from './core/services/msal-stub.service';
import { environment } from '../environments/environment';

export const appConfig: ApplicationConfig = {
  providers: [
    provideRouter(routes),
    provideHttpClient(withInterceptors([authInterceptor, errorInterceptor])),
    // ガードクラスのDI登録
    AuthGuardT,
    PermissionGuardT,
    
    // MSALサービス切り替え（環境設定による）
    // スタブ設定が有効な場合は MsalStubService を使用
    environment.useMsalStub
      ? {
          provide: MSAL_SERVICE,
          useClass: MsalStubService,
        }
      : {
          provide: MSAL_SERVICE,
          useClass: MsalService,
        },
    
    // スタブ用データの設定
    {
      provide: MSAL_STUB_DATA,
      useValue: environment.useMsalStub
        ? (environment.stubUserData as MsalStubData)
        : DEFAULT_STUB_DATA
    },
    
    // MSALインスタンスファクトリー
    {
      provide: MSAL_INSTANCE_FACTORY,
      useValue: defaultMsalFactory
    },
    
    // MSAL初期化（アプリ起動時に実行）
    provideAppInitializer(() => {
      const msalService = inject(MSAL_SERVICE);
      // MsalService のみ initialize() メソッドを持つ
      if (msalService instanceof MsalService) {
        return msalService.initialize();
      }
      return Promise.resolve();
    })
  ]
};
