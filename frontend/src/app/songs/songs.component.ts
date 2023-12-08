import { Component, OnInit } from '@angular/core';
import { FormBuilder, FormGroup } from '@angular/forms';
import { Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { SongService } from '../song.service';
import { UserService } from '../user.service';

@Component({
  selector: 'app-songs',
  templateUrl: './songs.component.html',
  styleUrls: ['./songs.component.css'],
})
export class SongsComponent implements OnInit {
  songs: any[] = [];
  displayedSongs: any[] = [];
  searchForm: FormGroup;

  constructor(
    private songService: SongService,
    private userService: UserService,
    private router: Router,
    private toastr: ToastrService,
    private fb: FormBuilder
  ) {
    this.searchForm = this.fb.group({
      searchQuery: [''],
    });
  }

  ngOnInit(): void {
    this.loadSongs();
  }

  loadSongs(): void {
    this.songService.getAllSongs().subscribe(
      (data: any[]) => {
        this.songs = data.map((song: any) => ({
          ...song,
          audioUrl: this.songService.getAudioUrl(song.audioUrl),
          logoUrl: this.songService.getLogoUrl(song.logoUrl),
        }));
        this.displayedSongs = [...this.songs];
        this.toastr.success('Canciones cargadas exitosamente');
      },
      (error) => {
        console.error('Error loading songs:', error);
        this.toastr.error('Error al cargar canciones');
      }
    );
  }

  playSong(songId: string): void {
    this.router.navigate(['/song-player', songId]);
  }

  editSong(song: any): void {
    this.router.navigate(['/upload', { songId: song._id }]);
  }

  deleteSong(song: any): void {
    const confirmDelete = confirm(`¿Eliminar "${song.title}" de ${song.artist}?`);
    if (confirmDelete) {
      this.songService.deleteSong(song._id).subscribe(
        (deletedSong) => {
          this.songs = this.songs.filter((s) => s._id !== song._id);
          this.displayedSongs = [...this.songs];
          this.toastr.success('Canción eliminada exitosamente');
        },
        (error) => {
          console.error('Error deleting song:', error);
          this.toastr.error('Error al eliminar la canción');
        }
      );
    }
  }

  searchSongs(): void {
    const query = this.searchForm.value.searchQuery.toLowerCase();
    this.displayedSongs = this.songs.filter(
      (song) =>
        song.title.toLowerCase().includes(query) ||
        song.artist.toLowerCase().includes(query)
    );
  }

  logout(): void {
    this.userService.logout();
    this.toastr.success('Sesión cerrada exitosamente');
    this.router.navigate(['/login']);
  }
  
  refreshPage(): void {
    location.reload();
  }

  showSuccess(): void {
    this.toastr.success('Operación exitosa');
  }

  showError(): void {
    this.toastr.error('Ocurrió un error');
  }
}
