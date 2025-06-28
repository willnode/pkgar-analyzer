const dropZone = document.getElementById('dropZone');
const output = document.getElementById('output');
const progressBar = document.getElementById('progressBar');

dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  dropZone.style.borderColor = '#00f';
});

dropZone.addEventListener('dragleave', e => {
  dropZone.style.borderColor = '#888';
});

dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.style.borderColor = '#888';
  const file = e.dataTransfer.files[0];
  file && file.arrayBuffer().then(x => analyzeFile(x));
});

async function downloadFileWithProgress(url) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`HTTP error ${response.status}`);

  const contentLength = response.headers.get('Content-Length');
  if (!contentLength) throw new Error('Content-Length response header missing');

  const total = parseInt(contentLength, 10);
  let loaded = 0;
  const chunks = [];

  const reader = response.body.getReader();
  progressBar.style.display = 'block';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    loaded += value.length;
    progressBar.value = (loaded / total) * 100;
  }

  const blob = new Blob(chunks);
  const arrayBuffer = await blob.arrayBuffer();
  analyzeFile(arrayBuffer);
}


function analyzeFile(arrayBuffer) {
  const dataView = new DataView(arrayBuffer);

  const header = {
    signature: new Uint8Array(arrayBuffer, 0, 64),
    publicKey: new Uint8Array(arrayBuffer, 64, 32),
    headerBlake3: new Uint8Array(arrayBuffer, 96, 32),
    count: dataView.getBigUint64(128, true)
  };

  let outputText = `== HEADER ==\n`;
  outputText += `Signature: ${[...header.signature].map(b => b.toString(16).padStart(2, '0')).join('')}\n`;
  outputText += `Public Key: ${[...header.publicKey].map(b => b.toString(16).padStart(2, '0')).join('')}\n`;
  outputText += `Header blake3: ${[...header.headerBlake3].map(b => b.toString(16).padStart(2, '0')).join('')}\n`;
  outputText += `Entry count: ${header.count}\n\n`;

  const entryBaseOffset = 136n;
  const entrySize = 308n;

  for (let i = 0n; i < header.count; i++) {
    const base = Number(entryBaseOffset + i * entrySize);
    const entryBlake3 = new Uint8Array(arrayBuffer, base, 32);
    const offset = new DataView(arrayBuffer, base + 32, 8).getBigUint64(0, true);
    const size = new DataView(arrayBuffer, base + 40, 8).getBigUint64(0, true);
    const mode = new DataView(arrayBuffer, base + 48, 4).getUint32(0, true);
    const modeParsed = parseMode(mode);
    const pathBytes = new Uint8Array(arrayBuffer, base + 52, 256);
    const path = new TextDecoder().decode(pathBytes).replace(/\0.*$/, '');

    outputText += `== ENTRY ${i + 1n} ==\n`;
    outputText += `File blake3: ${[...entryBlake3].map(b => b.toString(16).padStart(2, '0')).join('')}\n`;
    outputText += `Offset: ${offset} bytes, Size: ${size} bytes\n`;
    outputText += `Mode: ${modeParsed.permOctal} (${modeParsed.permSymbolic}), Type: ${modeParsed.kind}\n`;
    outputText += `Path: ${path}\n\n`;
  }

  output.textContent = outputText;
}

function parseMode(mode) {
  const PERM = 0o007777;
  const KIND = 0o170000;
  const FILE = 0o100000;
  const SYMLINK = 0o120000;

  const kindBits = mode & KIND;
  const permBits = mode & PERM;

  let kind = 'Other';
  if (kindBits === FILE) kind = 'File';
  else if (kindBits === SYMLINK) kind = 'Symlink';

  function toSymbolic(perm) {
    const symbols = ['r', 'w', 'x'];
    let result = '';
    for (let i = 6; i >= 0; i -= 3) {
      let triplet = (perm >> i) & 0b111;
      for (let j = 0; j < 3; j++) {
        result += (triplet & (1 << (2 - j))) ? symbols[j] : '-';
      }
    }
    return result;
  }

  return {
    kind,
    permOctal: '0o' + permBits.toString(8).padStart(4, '0'),
    permSymbolic: toSymbolic(permBits)
  };
}

// On page load: check if URL contains ?path=
window.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const path = urlParams.get('path');
  if (path) {
    const targetUrl = path.startsWith('http') ? path : `https://static.redox-os.org/pkg/${path}`;
    downloadFileWithProgress(targetUrl).catch(err => {
      console.error('Download failed:', err);
    });
  }
});
