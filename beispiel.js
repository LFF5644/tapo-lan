// TAPO_USER=mail TAPO_PASS=pw TAPO_IP=device_ip node beispiel.js
const { Tapo } = require('./tapo');

const tapo = new Tapo({ user: process.env.TAPO_USER, pass: process.env.TAPO_PASS });

// Globale Events (erstes Argument = Gerät)
tapo.on('offline', (d, err) => console.log(`[${d.name}] offline (${err.code})`));
tapo.on('online',  d => console.log(`[${d.name}] wieder online`));
tapo.on('reauth',  d => console.log(`[${d.name}] Session erneuert`));
tapo.on('error',   (d, e) => console.log(`[${d.name}] Fehler:`, e.message));
tapo.on('change',  (d, topic, neu, alt) => topic === 'state' && console.log(`[${d.name}] ${alt} -> ${neu}`));

(async () => {
  const device = await tapo.connect(process.env.TAPO_IP);            // -> P100 (TPAP/KLAP automatisch)

  console.log(await device.getInfo());
  console.log(await device.getDeviceUsage());
  await device.toggle();

  // Gerätespezifische Events
  device.on('state', on => console.log('device ist', on ? 'AN' : 'AUS'));

  // Hintergrund-Überwachung (Standard: aus)
  device.watch(5e3, 'state');
  // pc.watch(1e3, 'currentPower');
  // pc.watch(10e3, 'energyUsage');
  // pc.on('currentPower', p => console.log('Leistung:', p));

  // Beenden: alle Watches stoppen -> Prozess endet
  setTimeout(() => tapo.unwatchAll(), 30e3);
})().catch(e => console.error('Fehler:', e.message));
