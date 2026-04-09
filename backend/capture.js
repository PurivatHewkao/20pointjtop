const { spawn } = require('child_process');

let tshark = null;
let capturing = false;
let currentIface = '';
let stats = {
  total: 0,
  encrypted: 0,
  unencrypted: 0,
  protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
  startTime: null
};
let statsTimer = null;
let packetId = 0;

function normalizeProtocol(proto) {
  if (!proto) return 'OTHER';
  const p = proto.toUpperCase();
  if (p.includes('TLS') || p.includes('HTTPS')) return 'HTTPS';
  if (p.includes('SSH')) return 'SSH';
  if (p.includes('DNS')) return 'DNS';
  if (p.includes('HTTP')) return 'HTTP';
  if (p.includes('TCP')) return 'TCP';
  if (p.includes('UDP')) return 'UDP';
  if (p.includes('ICMP')) return 'ICMP';
  return 'OTHER';
}

function isEncrypted(proto) {
  if (!proto) return false;
  const p = proto.toUpperCase();
  return p.includes('TLS') || p.includes('HTTPS') || p.includes('SSH');
}

function tlsVersionFromProto(proto) {
  if (!proto) return '-';
  const p = proto.toUpperCase();
  if (p.includes('TLS 1.3')) return 'TLS 1.3';
  if (p.includes('TLS 1.2')) return 'TLS 1.2';
  if (p.includes('TLS 1.1')) return 'TLS 1.1';
  if (p.includes('TLS 1.0')) return 'TLS 1.0';
  if (p.includes('SSL')) return 'SSL 3.0';
  if (p.includes('SSH')) return 'SSH-2.0';
  if (p.includes('HTTPS')) return 'TLS 1.3';
  return '-';
}

function emitStats(io) {
  if (!io) return;
  const elapsed = stats.startTime ? (Date.now() - stats.startTime) / 1000 : 1;
  io.emit('stats', {
    total: stats.total,
    encrypted: stats.encrypted,
    unencrypted: stats.unencrypted,
    encryptedPct: stats.total > 0 ? Math.round((stats.encrypted / stats.total) * 100) : 0,
    protocols: { ...stats.protocols },
    pps: Math.round(stats.total / Math.max(1, elapsed)),
    uptime: Math.round(elapsed)
  });
}

function resetStats() {
  stats = {
    total: 0,
    encrypted: 0,
    unencrypted: 0,
    protocols: { HTTPS: 0, HTTP: 0, DNS: 0, SSH: 0, TCP: 0, UDP: 0, ICMP: 0, OTHER: 0 },
    startTime: Date.now()
  };
  packetId = 0;
}

function emitPacket(io, pkt) {
  if (!pkt || !io) return;

  stats.total += 1;
  if (pkt.encrypted) stats.encrypted += 1;
  else stats.unencrypted += 1;

  if (stats.protocols[pkt.protocol] !== undefined) stats.protocols[pkt.protocol] += 1;
  else stats.protocols.OTHER += 1;

  io.emit('packet', pkt);
  if (stats.total % 50 === 0) emitStats(io);
}

function parseLine(line) {
  const [src, dst, tcpSrc, tcpDst, udpSrc, udpDst, proto, len] = line.split('\t');
  if (!src || !dst) return null;

  const srcPort = tcpSrc || udpSrc || '-';
  const dstPort = tcpDst || udpDst || '-';
  const protocol = normalizeProtocol(proto);
  const encrypted = isEncrypted(proto);
  const tlsVersion = tlsVersionFromProto(proto);
  const size = parseInt(len, 10) || 0;

  return {
    id: ++packetId,
    timestamp: new Date().toISOString(),
    time: new Date().toLocaleTimeString('th-TH'),
    srcIP: src,
    dstIP: dst,
    srcPort,
    dstPort,
    protocol,
    size,
    tlsVersion: tlsVersion || '-',
    encrypted
  };
}

function startTshark(io, iface = '5', filter = '') {
  const tsharkPath = 'C:\\Program Files\\Wireshark\\tshark.exe';
  const args = [
    '-i', iface,
    '-l',
    '-T', 'fields',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-e', 'tcp.srcport',
    '-e', 'tcp.dstport',
    '-e', 'udp.srcport',
    '-e', 'udp.dstport',
    '-e', '_ws.col.Protocol',
    '-e', 'frame.len'
  ];
  if (filter) args.push('-Y', filter);

  tshark = spawn(tsharkPath, args, { windowsHide: true });
  capturing = true;
  currentIface = iface;

  tshark.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');
    lines.forEach((line) => {
      if (!line.trim()) return;
      const pkt = parseLine(line);
      if (pkt) emitPacket(io, pkt);
    });
  });

  tshark.stderr.on('data', (err) => {
    console.error('[tshark]', err.toString());
    if (io) io.emit('error', { message: err.toString() });
  });

  tshark.on('exit', (code, signal) => {
    capturing = false;
    tshark = null;
    if (io) io.emit('capture:status', { capturing: false });
    console.log(`tshark exited code=${code} signal=${signal}`);
  });

  if (statsTimer) clearInterval(statsTimer);
  statsTimer = setInterval(() => emitStats(io), 2000);

  io.emit('capture:status', { capturing: true, interface: iface });
  emitStats(io);
}

function stopTshark() {
  capturing = false;
  if (tshark) {
    try {
      tshark.kill();
    } catch (err) {
      console.error('Failed to stop tshark:', err.message);
    }
    tshark = null;
  }
  if (statsTimer) {
    clearInterval(statsTimer);
    statsTimer = null;
  }
}

module.exports = {
  start(iface = '5', filter = '', io) {
    if (capturing) {
      stopTshark();
    }
    resetStats();
    startTshark(io, iface, filter);
  },

  stop() {
    stopTshark();
  },

  isCapturing: () => capturing,
  getInterface: () => currentIface,
  getStats: () => ({ ...stats })
};