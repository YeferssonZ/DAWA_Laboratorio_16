import { NgModule } from '@angular/core';
import { BrowserModule } from '@angular/platform-browser';
import { FormsModule, ReactiveFormsModule } from '@angular/forms';
import { AppRoutingModule } from './app-routing.module';
import { AppComponent } from './app.component';
import { LoginComponent } from './login/login.component';
import { SongsComponent } from './songs/songs.component';
import { HttpClientModule } from '@angular/common/http';
import { RegisterComponent } from './register/register.component';
import { UploadComponent } from './upload/upload.component';
import { SongPlayerComponent } from './song-player/song-player.component';
import { ToastNoAnimation, ToastrModule } from 'ngx-toastr';
import { BrowserAnimationsModule } from '@angular/platform-browser/animations';
import { NgbModule } from '@ng-bootstrap/ng-bootstrap';
import { AuthGuard } from './auth.guard';

@NgModule({
  declarations: [
    AppComponent,
    LoginComponent,
    SongsComponent,
    RegisterComponent,
    UploadComponent,
    SongPlayerComponent,
  ],
  imports: [
    BrowserModule,
    FormsModule, 
    HttpClientModule,
    AppRoutingModule,
    ReactiveFormsModule,
    BrowserAnimationsModule,
    ToastrModule.forRoot({
      positionClass: 'toast-top-center',
      preventDuplicates: true,
      progressBar: true,
      progressAnimation: 'increasing',
      timeOut: 3000,
      extendedTimeOut: 1000,
      closeButton: false,
      easeTime: 300,
      maxOpened: 3,
      newestOnTop: true,
      countDuplicates: true,
      disableTimeOut: false,
      toastComponent: ToastNoAnimation,
      toastClass: 'custom-toast',
    }),
    NgbModule,
  ],
  providers: [AuthGuard],
  bootstrap: [AppComponent]
})
export class AppModule { }
