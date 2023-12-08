import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, throwError, of } from 'rxjs';
import { catchError, tap } from 'rxjs/operators';
import { ToastrService } from 'ngx-toastr';

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private apiUrl = 'http://localhost:3000/api/users';

  constructor(private http: HttpClient, private toastr: ToastrService) { }

  login(username: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/login`, { username, password })
      .pipe(
        tap((response: any) => {
          // Almacena el token en el localStorage
          localStorage.setItem('authToken', response.token);
          // Muestra el Toast de login exitoso
          this.toastr.success('Inicio de sesión exitoso', '¡Bienvenido!');
          
          // Agrega un mensaje de consola para depuración
          console.log('Token después del inicio de sesión:', this.getAuthToken());
        }),
        catchError(this.handleError)
      );
  }

  register(username: string, password: string): Observable<any> {
    return this.http.post(`${this.apiUrl}/register`, { username, password })
      .pipe(
        tap((response: any) => {
          // Almacena el token en el localStorage
          localStorage.setItem('authToken', response.token);
          // Muestra el Toast de registro exitoso
          this.toastr.success('Usuario registrado exitosamente', '¡Bienvenido!');
        }),
        catchError(this.handleError)
      );
  }

  getAuthToken(): string | null {
    // Devuelve el token almacenado en el localStorage
    return localStorage.getItem('authToken');
  }

  logout(): void {
    // Elimina el token del localStorage al cerrar sesión
    localStorage.removeItem('authToken');
    console.log('Token eliminado al cerrar sesión');
  }

  private handleError(error: any): Observable<any> {
    console.error('Error:', error);
    return throwError(error);
  }

  // En tu servicio de usuario (user.service.ts)
  isLoggedIn(): boolean {
    // Verifica si existe un token en el localStorage
    return !!localStorage.getItem('authToken');
  }


}
