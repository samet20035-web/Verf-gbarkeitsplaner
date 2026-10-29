// Baut beim Deploy die verschlüsselte index.html.
// Benötigt die GitHub-Secrets BENUTZERKENNUNG, PASSWORT und APP_B64.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { pbkdf2Sync, randomBytes, createCipheriv } from 'node:crypto';
import { gunzipSync } from 'node:zlib';

const ITER = 600000;
const clean = (v) => (v || '').replace(/\s/g, '');
const fail = (msg) => { console.error('FEHLER: ' + msg); process.exit(1); };

const kennung = clean(process.env.BENUTZERKENNUNG);
const passwort = clean(process.env.PASSWORT);
const appB64 = clean(process.env.APP_B64);

if (!kennung || !passwort) fail('Secret BENUTZERKENNUNG oder PASSWORT fehlt (Settings → Secrets and variables → Actions).');
if (!/^[0-9]+$/.test(kennung) || !/^[0-9]+$/.test(passwort)) fail('BENUTZERKENNUNG und PASSWORT dürfen nur Ziffern enthalten.');
if (kennung.length + passwort.length < 10) fail('BENUTZERKENNUNG und PASSWORT zusammen brauchen mindestens 10 Ziffern.');
if (!appB64) fail('Secret APP_B64 fehlt (Inhalt der Datei APP_B64.txt).');

const iconUri = 'data:image/png;base64,' + readFileSync('icon.png').toString('base64');

let app;
try { app = gunzipSync(Buffer.from(appB64, 'base64')).toString('utf8'); }
catch { fail('APP_B64 ist unvollständig oder beschädigt. Bitte den Secret neu einfügen.'); }
if (!app.includes('<html') || !app.includes('Verfügbarkeitsplaner')) fail('APP_B64 enthält nicht die Planer-App.');
app = app.split('__ICON__').join(iconUri);

const salt = randomBytes(16), iv = randomBytes(12);
const key = pbkdf2Sync(`${kennung}:${passwort}`, salt, ITER, 32, 'sha256');
const c = createCipheriv('aes-256-gcm', key, iv);
const ct = Buffer.concat([c.update(app, 'utf8'), c.final(), c.getAuthTag()]); // Tag hinten, wie WebCrypto es erwartet
const payload = Buffer.concat([salt, iv, ct]).toString('base64');

const gate = readFileSync('gate.template.html', 'utf8')
  .split('__ICON__').join(iconUri)
  .split('__PAYLOAD__').join(payload)
  .split('__ITER__').join(String(ITER));

mkdirSync('dist', { recursive: true });
writeFileSync('dist/index.html', gate);
console.log('OK: dist/index.html erstellt (' + gate.length + ' Zeichen).');
