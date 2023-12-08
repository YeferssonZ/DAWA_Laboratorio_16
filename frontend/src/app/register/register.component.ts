import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { UserService } from '../user.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css'],
})
export class RegisterComponent implements OnInit {
  registerForm: FormGroup;
  passwordMinLength = 5; // Mínimo de caracteres para la contraseña

  constructor(private userService: UserService, private router: Router, private fb: FormBuilder) {
    this.registerForm = this.fb.group({
      username: ['', Validators.required],
      password: ['', [Validators.required, Validators.minLength(this.passwordMinLength)]],
    });
  }

  ngOnInit(): void {}

  register(): void {
    if (this.registerForm.valid) {
      this.userService
        .register(this.registerForm.value.username, this.registerForm.value.password)
        .subscribe(
          (response) => {
            console.log(response);
            // Redirige al componente de canciones después del registro
            this.router.navigate(['/songs']);
          },
          (error) => {
            console.error('Error al registrar usuario:', error);
            // Maneja el error, muestra un mensaje, etc.
          }
        );
    } else {
      // Formulario no válido, muestra mensajes de error o indicadores visuales
      this.markFormGroupTouched(this.registerForm);
    }
  }

  // Función para marcar todo el FormGroup como tocado
  markFormGroupTouched(formGroup: FormGroup) {
    Object.values(formGroup.controls).forEach((control) => {
      control.markAsTouched();

      if (control instanceof FormGroup) {
        this.markFormGroupTouched(control);
      }
    });
  }
}
