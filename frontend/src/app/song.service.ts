import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Injectable({
  providedIn: 'root'
})
export class SongService {
  private apiUrl = 'http://localhost:3000/api/songs';

  constructor(private http: HttpClient) { }

  getAllSongs(): Observable<any[]> {
    return this.http.get<any[]>(this.apiUrl)
      .pipe(
        catchError(this.handleError)
      );
  }

  uploadSong(song: any): Observable<any> {
    return this.http.post(`${this.apiUrl}/upload`, song)
      .pipe(
        catchError(this.handleError)
      );
  }

  getAudioUrl(relativePath: string): string {
    return `http://localhost:3000/${relativePath}`;
  }

  getLogoUrl(relativeUrl: string): string {
    return `http://localhost:3000/${relativeUrl}`;
  }

  getSongById(songId: string): Observable<any> {
    return this.http.get(`${this.apiUrl}/${songId}`)
      .pipe(
        catchError(this.handleError)
      );
  }

  updateSong(songId: string, data: any): Observable<any> {
    return this.http.put(`${this.apiUrl}/${songId}`, data)
      .pipe(
        catchError(this.handleError)
      );
  }

  deleteSong(songId: string): Observable<any> {
    return this.http.delete(`${this.apiUrl}/${songId}`)
      .pipe(
        catchError(this.handleError)
      );
  }

  private handleError(error: any): Observable<any> {
    console.error('Error:', error);
    return throwError(error);
  }
}
