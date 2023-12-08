import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { UserService } from '../user.service';
import { Router } from '@angular/router';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css'],
})
export class LoginComponent implements OnInit {
  loginForm: FormGroup;
  authenticationError = false; // Nueva propiedad para manejar el estado de autenticación

  constructor(private userService: UserService, private router: Router, private fb: FormBuilder) {
    this.loginForm = this.fb.group({
      username: ['', Validators.required],
      password: ['', Validators.required],
    });
  }

  ngOnInit(): void {}

  login(): void {
    if (this.loginForm.valid) {
      this.userService.login(this.loginForm.value.username, this.loginForm.value.password)
        .subscribe(
          (response) => {
            console.log(response);
            // Redirige a la página de inicio después del inicio de sesión exitoso
            this.router.navigate(['/songs']);
          },
          (error) => {
            console.error('Error al iniciar sesión:', error);
            this.authenticationError = true; // Establece el estado de autenticación en true
          }
        );
    } else {
      // Muestra mensajes de error o indicadores visuales
      this.authenticationError = true; // Establece el estado de autenticación en true
    }
  }
}
