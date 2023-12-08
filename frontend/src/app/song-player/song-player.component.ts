import { Component, ElementRef, OnInit, ViewChild, NgZone } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ToastrService } from 'ngx-toastr';
import { SongService } from '../song.service';
import { saveAs } from 'file-saver';

@Component({
  selector: 'app-song-player',
  templateUrl: './song-player.component.html',
  styleUrls: ['./song-player.component.css'],
})
export class SongPlayerComponent implements OnInit {
  song: any = null;
  isPlaying: boolean = false;
  isMuted: boolean = false;
  volume: number = 100;
  currentTime: number = 0;
  totalTime: number = 0;
  currentSpeed = 1;

  @ViewChild('audioPlayer') audioPlayer!: ElementRef;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private songService: SongService,
    private toastr: ToastrService,
    private ngZone: NgZone
  ) {}

  ngOnInit(): void {
    this.route.params.subscribe((params) => {
      const songId = params['songId'];

      if (songId) {
        this.songService.getSongById(songId).subscribe(
          (data: any) => {
            this.song = {
              ...data,
              audioUrl: this.songService.getAudioUrl(data.audioUrl),
              logoUrl: this.songService.getLogoUrl(data.logoUrl),
            };
            this.showSuccess('Canción cargada exitosamente');
            this.initializeAudio();
          },
          (error) => {
            console.error('Error loading song:', error);
            this.showError('Error al cargar la canción');
          }
        );
      }
    });
  }

  initializeAudio(): void {
    const audio = this.audioPlayer.nativeElement;

    audio.addEventListener('loadedmetadata', () => {
      this.ngZone.run(() => {
        this.totalTime = audio.duration;
      });
    });

    audio.addEventListener('timeupdate', () => {
      this.ngZone.run(() => {
        this.currentTime = (audio.currentTime / audio.duration) * 100;
      });
    });
  }

  playPause(): void {
    const audio = this.audioPlayer.nativeElement;
    this.isPlaying = !this.isPlaying;

    if (this.isPlaying) {
      audio.play();
    } else {
      audio.pause();
    }
  }

  seekTo(event: any): void {
    const audio = this.audioPlayer.nativeElement;
    const seekTime = (event.target.value / 100) * audio.duration;
    audio.currentTime = seekTime;
  }

  toggleMute(): void {
    const audio = this.audioPlayer.nativeElement;
    this.isMuted = !this.isMuted;
    audio.muted = this.isMuted;
  }

  setVolume(event: any): void {
    const audio = this.audioPlayer.nativeElement;
    this.volume = event.target.value;
    audio.volume = this.volume / 100;
  }

  resetSpeed(): void {
    this.changeSpeed(1);
  }

  download(): void {
    const songUrl = this.song.audioUrl;

    fetch(songUrl)
      .then(response => response.blob())
      .then(songBlob => {
        saveAs(songBlob, `${this.song.title} - ${this.song.artist}.mp3`);
        this.showSuccess('Descarga completada');
      })
      .catch(error => {
        console.error('Error al descargar la canción:', error);
        this.showError('Error al descargar la canción');
      });
  }

  changeSpeed(speed: number): void {
    this.currentSpeed = speed;
    this.audioPlayer.nativeElement.playbackRate = this.currentSpeed;
  }
  
  adjustSpeed(factor: number): void {
    this.currentSpeed *= factor;
    this.audioPlayer.nativeElement.playbackRate = this.currentSpeed;
  }

  formatTime(time: number): string {
    const minutes = Math.floor(time / 60);
    const seconds = Math.floor(time % 60);
    const formattedMinutes = String(minutes).padStart(2, '0');
    const formattedSeconds = String(seconds).padStart(2, '0');
    return `${formattedMinutes}:${formattedSeconds}`;
  }

  showSuccess(message: string): void {
    this.toastr.success(message);
  }

  showError(message: string): void {
    this.toastr.error(message);
  }
  
  updateTime(): void {
    const audio = this.audioPlayer.nativeElement;
    this.ngZone.run(() => {
      this.currentTime = audio.currentTime;
    });
  }
  
  updateTotalTime(): void {
    const audio = this.audioPlayer.nativeElement;
    this.totalTime = audio.duration;
  }

  goToSongs() {
    this.router.navigate(['/songs']);
  }
}
