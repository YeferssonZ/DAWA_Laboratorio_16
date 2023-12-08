import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ActivatedRoute, Router } from '@angular/router';
import { SongService } from '../song.service';
import { ToastrService } from 'ngx-toastr';

@Component({
  selector: 'app-upload',
  templateUrl: './upload.component.html',
  styleUrls: ['./upload.component.css'],
})
export class UploadComponent implements OnInit {
  uploadForm: FormGroup;
  isEditMode: boolean = false;
  songId: string | null = null;

  constructor(
    private fb: FormBuilder,
    private songService: SongService,
    private router: Router,
    private route: ActivatedRoute,
    private toastr: ToastrService
  ) {
    this.uploadForm = this.fb.group({
      title: ['', [Validators.required]],
      artist: ['', [Validators.required]],
      audio: [null, [Validators.required]],
      logo: [null, [Validators.required]],
    });
  }

  ngOnInit(): void {
    this.route.params.subscribe((params) => {
      this.songId = params['songId'];
      if (this.songId) {
        this.isEditMode = true;
        this.songService.getSongById(this.songId).subscribe(
          (data) => {
            this.uploadForm.patchValue(data);
            // Deshabilitar validación para campos de archivo en modo de edición
            const audioControl = this.uploadForm.get('audio');
            if (audioControl) {
              audioControl.clearValidators();
              audioControl.updateValueAndValidity();
            }
  
            const logoControl = this.uploadForm.get('logo');
            if (logoControl) {
              logoControl.clearValidators();
              logoControl.updateValueAndValidity();
            }
          },
          (error) => {
            console.error('Error loading song for edit:', error);
          }
        );
      }
    });
  }
  

  onAudioChange(event: any): void {
    const file = event.target.files[0];
    this.uploadForm.patchValue({ audio: file });
  }

  onLogoChange(event: any): void {
    const file = event.target.files[0];
    this.uploadForm.patchValue({ logo: file });
  }

  uploadSong(): void {
    if (this.uploadForm.valid) {
      const formData = new FormData();
      formData.append('title', this.uploadForm.value.title);
      formData.append('artist', this.uploadForm.value.artist);
      formData.append('audio', this.uploadForm.value.audio);
      formData.append('logo', this.uploadForm.value.logo);
  
      const serviceCall = this.isEditMode
        ? this.songService.updateSong(this.songId as string, this.uploadForm.value)
        : this.songService.uploadSong(formData);
  
      serviceCall.subscribe(
        (response) => {
          if (this.isEditMode) {
            this.toastr.success('Canción actualizada exitosamente'); // Mostrar mensaje de éxito
            console.log('Song updated successfully', response);
            this.router.navigate(['/songs']);
          } else {
            this.toastr.success('Canción subida exitosamente'); // Mostrar mensaje de éxito
            console.log('Song uploaded successfully', response);
            this.router.navigate(['/songs']);
          }
        },
        (error) => {
          console.error(this.isEditMode ? 'Error updating song' : 'Error uploading song', error);
          // Puedes mostrar mensajes de error más específicos al usuario aquí
        }
      );
    } else {
      this.validateAllFormFields(this.uploadForm);
    }
  }
 
  validateAllFormFields(formGroup: FormGroup) {
    Object.keys(formGroup.controls).forEach((field) => {
      const control = formGroup.get(field);
      if (control instanceof FormGroup) {
        this.validateAllFormFields(control);
      } else {
        control?.markAsTouched({ onlySelf: true });
      }
    });
  }
  
  goToSongs() {
    this.router.navigate(['/songs']);
  }
}
