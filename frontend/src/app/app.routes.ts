import { Routes } from '@angular/router';
import { authAndPermissionGuard, authAndPermissionChildGuard } from './core/guards/auth-and-permission.guard';

export const routes: Routes = [
  { path: '', redirectTo: '/login', pathMatch: 'full' },
  {
    path: 'login',
    loadComponent: () => import('./auth/login.component').then(m => m.LoginComponent)
  },
  {
    path: 'callback',
    loadComponent: () => import('./auth/callback.component').then(m => m.CallbackComponent)
  },
  {
    path: 'dashboard',
    loadComponent: () => import('./business/dashboard.component').then(m => m.DashboardComponent),
    canActivate: [authAndPermissionGuard]
  },
  {
    path: 'menu',
    loadComponent: () => import('./business/menu.component').then(m => m.MenuComponent),
    canActivate: [authAndPermissionGuard]
  },
  {
    path: 'business/data',
    loadComponent: () => import('./business/sample-data.component').then(m => m.SampleDataComponent),
    canActivate: [authAndPermissionGuard],
    data: { screenId: 'BUSINESS_DATA_SCREEN' }
  },
  {
    path: 'admin/management',
    loadComponent: () => import('./business/admin-management.component').then(m => m.AdminManagementComponent),
    canActivate: [authAndPermissionGuard],
    data: { screenId: 'ADMIN_MANAGEMENT_SCREEN' }
  },
  {
    path: 'settings',
    loadComponent: () => import('./business/settings/settings.component').then(m => m.SettingsComponent),
    canActivateChild: [authAndPermissionChildGuard],
    data: { screenId: 'SETTINGS_SCREEN' }
  },
  {
    path: 'error/auth',
    loadComponent: () => import('./shared/auth-error.component').then(m => m.AuthErrorComponent)
  },
  {
    path: 'error/forbidden',
    loadComponent: () => import('./shared/forbidden-error.component').then(m => m.ForbiddenErrorComponent)
  },
  {
    path: 'logout',
    loadComponent: () => import('./auth/logout-complete.component').then(m => m.LogoutCompleteComponent)
  },
  { path: '**', redirectTo: '/login' }
];
