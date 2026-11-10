# tapo-lan

Lokale Steuerung von TP-Link-Tapo-Steckdosen (P100/P110 u. a.) im LAN, ohne Cloud und ohne Abhängigkeiten.
Spricht **KLAP** (mit „Third-Party Compatibility“) und **TPAP / SPAKE2+** (ohne „Third-Party Compatibility“, neuere Firmware) und erkennt das Protokoll automatisch.

- Ohne npm-Abhängigkeiten, nur `http`, `crypto` und `events` aus Node
- Promise-API mit `getX()`/`setX()` und EventEmitter (`.on`/`.once`)
- Optionales Polling pro Thema mit `watch(ms, ...topics)` und `unwatch()`
- Session-Erneuerung (genau **1** Neuversuch) und Offline/Online-Erkennung
- Pro Gerät eine Warteschlange, Anfragen laufen nie parallel

> Node.js **>= 18**

---

## Inhalt

- [Installation](#installation)
- [Quickstart](#quickstart)
- [Unterstützte Geräte](#unterstützte-geräte)
- [API](#api)
  - [`Tapo`](#tapo-hub)
  - [`TapoDevice` / `P100`](#tapodevice--p100)
  - [`P110`](#p110)
  - [`TapoError`](#tapoerror)
- [Events](#events)
- [Watch / Unwatch](#watch--unwatch)
- [Verbindung, Session & Offline-Verhalten](#verbindung-session--offline-verhalten)
- [Rohzugriff: `request()`](#rohzugriff-request)
- [Debugging](#debugging)
- [Protokolle](#protokolle)
- [Bekannte Grenzen](#bekannte-grenzen)
- [Credits & Lizenz](#credits--lizenz)

---

## Installation

```bash
npm install tapo-lan
# oder direkt aus dem Repo
npm install github:LFF5644/tapo-lan
```

## Quickstart

```js
const { Tapo } = require('tapo-lan');

const tapo = new Tapo({ user: 'mail@example.com', pass: 'tapo-passwort' });

tapo.on('offline', (dev, err) => console.log(dev.name, 'offline', err.code));
tapo.on('online',  dev => console.log(dev.name, 'online'));

(async () => {
  const kette = await tapo.connect('192.168.178.23');          // -> P100
  const pc    = await tapo.connect('192.168.178.30', { name: 'PC' }); // -> P110

  await kette.toggle();
  console.log(await pc.getCurrentPower());

  pc.on('currentPower', p => console.log('Leistung', p));
  pc.watch(1e3, 'currentPower');
  pc.watch(10e3, 'energyUsage');
  kette.watch(5e3, 'state', 'info');
})();
```

`user` und `pass` sind die Zugangsdaten des **TP-Link/Tapo-Kontos**, nicht das WLAN-Passwort.

---

## Unterstützte Geräte

| Modell | Klasse | Zusätzliche Methoden |
|---|---|---|
| P100, P105 | `P100` | – |
| P110, P110M, P115 | `P110` | `getCurrentPower()`, `getEnergyUsage()` |
| alle anderen | `TapoDevice` | – (Basisfunktionen + `request()`) |

Die Klasse wird bei `tapo.connect()` anhand von `get_device_info.model` gewählt.
Live getestet: **P100, FW 1.4.6** (TPAP und KLAP). P110 ist gegen ein simuliertes Gerät getestet.

---

## API

### `Tapo` (Hub)

```js
const tapo = new Tapo({ user, pass });
```

`Tapo` erbt von `EventEmitter`. Alle Geräte-Events werden zusätzlich am Hub ausgelöst, mit dem Gerät als **erstem** Argument (siehe [Events](#events)).

| Member | Typ / Rückgabe | Beschreibung |
|---|---|---|
| `new Tapo({ user, pass })` | `Tapo` | Wirft `TypeError`, wenn `user`/`pass` fehlen. |
| `connect(ip, opts?)` | `Promise<P100 \| P110 \| TapoDevice>` | Meldet sich an, liest das Modell aus, liefert die passende Klasse und legt das Gerät in `devices` ab. |
| `device(name)` | `TapoDevice \| undefined` | Gerät aus `devices` nach Name. |
| `devices` | `Map<string, TapoDevice>` | Alle per `connect()` verbundenen Geräte. Schlüssel ist `name`; doppelte Namen überschreiben. |
| `unwatchAll()` | `this` | Stoppt alle Watches aller Geräte. |
| `user`, `pass` | `string` | Zugangsdaten (werden beim nächsten Login verwendet). |

**`connect()`-Optionen**

| Option | Default | Beschreibung |
|---|---|---|
| `name` | Gerätename aus der App (`nickname`), sonst `ip` | Anzeigename und Schlüssel in `devices` |
| `port` | `80` | HTTP-Port des Geräts |
| `protocol` | `'auto'` | `'auto'` \| `'tpap'` \| `'klap'` |

Bei `'auto'` wird zuerst `discover` ohne Zugangsdaten gesendet: `tpap_preferred: true` → TPAP, sonst KLAP.

---

### `TapoDevice` / `P100`

`P100` erbt ohne Änderungen von `TapoDevice`. Alle Geräte erben von `EventEmitter`.

#### Methoden

| Methode | Rückgabe | Request | Events |
|---|---|---|---|
| `getInfo()` | `Promise<object>` | `get_device_info` | `state`, `info` |
| `getState()` | `Promise<boolean>` | `get_device_info` | `state` |
| `getDeviceUsage()` | `Promise<object>` | `get_device_usage` | `deviceUsage` |
| `setState(on)` | `Promise<boolean>` | `set_device_info { device_on }` | `state` |
| `turnOn()` | `Promise<true>` | wie `setState(true)` | `state` |
| `turnOff()` | `Promise<false>` | wie `setState(false)` | `state` |
| `toggle()` | `Promise<boolean>` (neuer Zustand) | `getState()` + `setState()` | `state` (2×) |
| `request(method, params?)` | `Promise<object>` | beliebig | – (siehe [Rohzugriff](#rohzugriff-request)) |
| `watch(ms, ...topics)` | `this` | – | siehe [Watch](#watch--unwatch) |
| `unwatch(...topics)` | `this` | – | – |

Bei jedem Getter werden **zusätzlich** Events ausgelöst (wenn Listener registriert sind). Man kann also das Promise nutzen, die Events, oder beides.

#### Rückgabewerte

Alle `get*()`-Ergebnisse sind **rekursiv nach camelCase umgewandelt** (`device_on` → `deviceOn`, `fw_ver` → `fwVer`, …). `nickname` und `ssid` sind bereits **base64-dekodiert**.

```js
await kette.getInfo();
// { deviceId, fwVer: '1.4.6 Build ...', hwVer, model: 'P100', type, mac,
//   deviceOn: true, onTime: 1234, nickname: 'Lichterkette', ssid, rssi, signalLevel, ... }
```

Welche Felder genau enthalten sind, hängt vom Gerät und der Firmware ab. Die Lib reicht sie unverändert durch, nur in camelCase.

#### Eigenschaften

| Eigenschaft | Typ | Beschreibung |
|---|---|---|
| `ip`, `port` | `string`, `number` | Adresse |
| `name` | `string` | Anzeigename |
| `model` | `string \| null` | z. B. `'P100'` |
| `protocol` | `'auto' \| 'tpap' \| 'klap'` | Konfiguriertes Protokoll |
| `online` | `boolean \| null` | `null` = noch unbekannt |
| `last` | `object` | Letzter Wert pro Thema, z. B. `last.state`, `last.currentPower` |
| `topics` | `string[]` (Getter) | Themen, die dieses Gerät per `watch` unterstützt |
| `watching` | `{ [topic]: ms }` (Getter) | Aktive Watches |
| `authBlocked` | `boolean` | `true` nach Auth-Fehler, Hintergrund-Polling pausiert |
| `hub` | `Tapo` | Zugehöriger Hub |

---

### `P110`

Erbt alles von `P100` und hat zusätzlich:

| Methode | Rückgabe | Request | Event |
|---|---|---|---|
| `getCurrentPower()` | `Promise<object>` | `get_current_power` | `currentPower` |
| `getEnergyUsage()` | `Promise<object>` | `get_energy_usage` | `energyUsage` |

```js
await pc.getCurrentPower();  // z. B. { currentPower: 76 }
await pc.getEnergyUsage();   // z. B. { todayEnergy, monthEnergy, todayRuntime, monthRuntime, currentPower, localTime, ... }
```

> Die Werte werden 1:1 vom Gerät durchgereicht (camelCase), ohne Einheiten-Umrechnung. Laut anderen Tapo-Libs ist `currentPower` in `get_current_power` in **W** und `currentPower` in `get_energy_usage` in **mW**. Bitte am eigenen Gerät prüfen.

---

### `TapoError`

Alle Fehler der Lib sind `TapoError extends Error`.

| Feld | Beschreibung |
|---|---|
| `message` | Lesbare Beschreibung |
| `code` | HTTP-Status, Geräte-`error_code` oder Node-Fehlercode (`ECONNREFUSED`, `TIMEOUT`, …) |
| `kind` | `'network'` \| `'auth'` \| `'session'` \| `'device'` |

| `kind` | Bedeutung | Verhalten der Lib |
|---|---|---|
| `network` | Gerät nicht erreichbar / Timeout | `online = false`, Event `offline` |
| `auth` | Login abgelehnt (Passwort falsch, KLAP-403 ohne Third-Party-Modus, …) | `authBlocked = true`, Watches pausieren |
| `session` | Session ungültig | intern: 1× neu anmelden, Event `reauth`; nur wenn das auch fehlschlägt, wird geworfen |
| `device` | Gerät antwortet mit `error_code != 0` (z. B. `-1` = Methode unbekannt) | wird nur geworfen |

```js
const { TapoError } = require('tapo-lan');
try { await kette.turnOn(); }
catch (e) { if (e instanceof TapoError && e.kind === 'auth') { /* ... */ } }
```

---

## Events

Jedes Event wird **am Gerät** und **am Hub** ausgelöst. Am Hub kommt das Gerät als erstes Argument dazu.

```js
kette.on('state', (on, old) => {});
tapo.on('state', (device, on, old) => {});
```

| Event | Argumente (Gerät) | Wann |
|---|---|---|
| `state` | `(on: boolean, old)` | nach `getInfo`, `getState`, `setState`, `turnOn/Off`, `toggle` |
| `info` | `(info, old)` | nach `getInfo` |
| `deviceUsage` | `(usage, old)` | nach `getDeviceUsage` |
| `currentPower` | `(power, old)` | nach `getCurrentPower` (P110) |
| `energyUsage` | `(usage, old)` | nach `getEnergyUsage` (P110) |
| `change` | `(topic, value, old)` | wie oben, aber **nur wenn sich der Wert geändert hat** (Vergleich per JSON) |
| `online` | `()` | erste erfolgreiche Anfrage nach `offline` |
| `offline` | `(err: TapoError)` | Netzwerkfehler, wenn das Gerät vorher online oder unbekannt war |
| `reauth` | `()` | Session war ungültig, neue Anmeldung hat geklappt |
| `error` | `(err: TapoError)` | Fehler bei einem **Watch**-Durchlauf (außer Netzwerkfehler → `offline`) |

**Hinweise**

- Themen-Events (`state`, `info`, …) feuern bei **jedem** Abruf, `change` nur bei Änderung.
- `old` ist beim ersten Wert `undefined`.
- `offline`/`online` feuern nur bei Zustandswechsel, nicht bei jedem Fehlversuch.
- `error` ohne Listener wird **ignoriert** und wirft nicht wie beim normalen `EventEmitter`.
- Ohne Watch passiert im Hintergrund nichts: `offline`/`reauth` kommen dann erst bei deinem nächsten eigenen Aufruf.
- `.once()`, `.off()`, `.removeAllListeners()` usw. funktionieren wie bei jedem `EventEmitter`.

```js
tapo.once('reauth', d => console.log('erste Session-Erneuerung:', d.name));
pc.on('change', (topic, v, old) => topic === 'state' && notify(v));
```

---

## Watch / Unwatch

```js
dev.watch(ms, ...topics)   // -> this
dev.unwatch(...topics)     // -> this, ohne Argumente = alle
tapo.unwatchAll()
```

| Thema | Getter | Geräte |
|---|---|---|
| `state` | `getState()` | alle |
| `info` | `getInfo()` | alle |
| `deviceUsage` | `getDeviceUsage()` | alle |
| `currentPower` | `getCurrentPower()` | P110 |
| `energyUsage` | `getEnergyUsage()` | P110 |

```js
kette.watch(5e3, 'state', 'info');          // beide Themen alle 5 s
pc.watch(1e3, 'currentPower');
pc.watch(10e3, 'energyUsage');
pc.watch(500, ['state', 'currentPower']);   // Array geht auch

pc.watching;                 // { state: 500, currentPower: 500, energyUsage: 10000 }
pc.unwatch('currentPower');
pc.unwatch();                // alle Themen dieses Geräts
pc.topics;                   // ['state', 'info', 'deviceUsage', 'currentPower', 'energyUsage']
```

**Verhalten**

- Ein Timer pro Thema, das Intervall ist in **ms** ohne Mindestwert.
- Der **erste Abruf startet sofort**, danach im Intervall.
- Ein erneutes `watch()` für ein Thema **ersetzt** dessen Intervall.
- Ist ein Abruf noch nicht fertig, wird der nächste **übersprungen**, nicht gestapelt.
- Alle Anfragen eines Geräts laufen über **eine Warteschlange**. Viele Themen mit kurzen Intervallen bremsen sich deshalb gegenseitig.
- Bei `authBlocked` werden Durchläufe übersprungen (siehe unten).
- Ein nicht unterstütztes Thema oder `ms <= 0` → `TypeError` beim Aufruf.
- Aktive Watches halten den Node-Prozess am Leben → `unwatchAll()` zum Beenden.

---

## Verbindung, Session & Offline-Verhalten

```
erste Anfrage ─► discover (ohne Login) ─► TPAP- oder KLAP-Login ─► Anfrage
                                                                     │
           Session ungültig ◄────────────────────────────────────────┘
                 │
                 └─► genau 1× neu anmelden ─► Event 'reauth' ─► Anfrage wiederholen
                                    │
                                    └─ schlägt fehl ─► Fehler wird geworfen (kein Loop)
```

| Situation | Was passiert |
|---|---|
| **Session abgelaufen** | 1× neu anmelden + Anfrage wiederholen → `reauth` |
| **Gerät offline** | `online = false`, `offline(err)`. Die nächste Anfrage oder der nächste Watch-Durchlauf versucht zuerst `discover` (ohne Login). Antwortet das Gerät wieder: Login → `online` |
| **Login abgelehnt** | `authBlocked = true`. **Watches pausieren**, damit das Gerät nicht durch zu viele Fehlversuche gesperrt wird. Eigene Aufrufe (`getState()` usw.) versuchen es weiterhin; nach erfolgreichem Login wird `authBlocked` wieder `false` und die Watches laufen weiter |

Es gibt **keine** Wiederholungs-Schleifen beim Login: Zu viele Fehlversuche können TPAP-Geräte vorübergehend sperren.

---

## Rohzugriff: `request()`

Für alle Methoden, für die es (noch) keinen Wrapper gibt:

```js
const res = await dev.request('get_schedule_rules');
await dev.request('set_device_info', { led_off: 1 });
```

- Gibt `result` des Geräts **roh** zurück (snake_case, nicht dekodiert)
- Läuft durch dieselbe Warteschlange, Session-Erneuerung und Offline-Logik
- Löst **keine** Themen-Events aus (nur ggf. `online`/`offline`/`reauth`)
- Gerät antwortet mit `error_code != 0` → `TapoError` mit `kind: 'device'`
- TPAP-Methoden müssen **snake_case** sein (camelCase → `error_code -1002`)

---

## Debugging

```bash
TAPO_DEBUG=1 node app.js
```

```
DEBUG POST / -> 200 (148B)
DEBUG pake_register: suite=1 iters=3000 enc=aes_128_ccm extra={"params":{"passwd_id":2},"type":"password_shadow"}
DEBUG Lichterkette: Login OK (tpap)
DEBUG POST /stok=.../ds -> 200 (737B)
```

Ausgabe auf `stderr`.

---

## Protokolle

| | KLAP v2 | TPAP |
|---|---|---|
| Wann | Third-Party Compatibility **an** | Third-Party Compatibility **aus** (neue Firmware, `tpap_preferred: true`) |
| Login | `/app/handshake1` + `/app/handshake2`, `sha256(sha1(user) + sha1(pass))` | `discover` → `pake_register` → `pake_share` (SPAKE2+ auf P-256, PBKDF2, HKDF) |
| Session | Cookie `TP_SESSIONID` | `stok` |
| Verschlüsselung | AES-128-CBC + SHA256-Signatur | AES-128/256-CCM oder ChaCha20-Poly1305 |
| Endpunkt | `/app/request?seq=` | `/stok=<id>/ds` |

TPAP unterstützt die Varianten `cipher_suites` (SHA256/SHA512, HMAC/CMAC) sowie `extra_crypt` `password_shadow` (passwd_id 2/3) und `password_sha_with_salt`. Die Punktrechnung auf P-256 ist mit `BigInt` umgesetzt (nicht constant-time; für ein LAN-Steuerungstool unkritisch).

---

## Bekannte Grenzen

- **Kein Netzwerk-Scan**: Geräte werden per IP angegeben (am besten eine feste IP im Router vergeben).
- **Keine Timer/Zeitpläne als Wrapper**: über `request()` nutzbar.
- **Nur Steckdosen** getestet. Lampen/Lichtstreifen haben eigene Methoden, die nur über `request()` erreichbar sind.
- **TLS-Variante von TPAP** (`tpap.tls: 1`) ist nicht implementiert, nur HTTP auf Port 80.
- Doppelte `name`s überschreiben sich in `tapo.devices`.

---

## Credits & Lizenz

- TPAP-Implementierung portiert von [raymondlo84/tapo-tpap-client](https://github.com/raymondlo84/tapo-tpap-client) (`tpap_proto.py`).
- Code und Doku entstanden mit **Claude Opus 5.5** (via Microsoft Copilot) zusammen mit [LFF5644](https://github.com/LFF5644).

Nicht offiziell, keine Verbindung zu TP-Link. „Tapo“ und „TP-Link“ sind Marken der TP-Link Systems Inc.

[MIT](LICENSE) © LFF5644
