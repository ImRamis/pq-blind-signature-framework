// snarkjs_engine/server.js

const express     = require('express');
const snarkjs     = require('snarkjs');
const fs          = require('fs').promises;
const path        = require('path');
const circomlibjs = require('circomlibjs');

const app = express();
app.use(express.json({ limit: '50mb' }));

const PORT = process.env.SNARK_ENGINE_PORT || 8081;
const HOST = process.env.SNARK_ENGINE_HOST || '127.0.0.1';

// BN128 base-field prime (Circom’s field)
const CIRCOM_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');

let cachedVKeys = {};

async function handleSnarkJsRequest(params) {
  try {
    const { algorithm, action, circuitName, inputs, proof, publicSignals } = params;
    if (!snarkjs[algorithm]) {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }

    const projectRoot = path.resolve(__dirname, '..');
    const wasmPath    = path.join(projectRoot, 'circuits', 'build', circuitName, `${circuitName}_js`,  `${circuitName}.wasm`);
    const zkeyPath    = path.join(projectRoot, 'circuits', 'keys', `${circuitName}_${algorithm}.zkey`);
    const vkeyPath    = path.join(projectRoot, 'circuits', 'keys', `${circuitName}_${algorithm}_vkey.json`);

    if (action === 'prove') {
      // 1) Truncate the two private witnesses to 248 bits
      if (inputs.message !== undefined && inputs.randomness !== undefined) {
        const BITS = 248n;
        const MASK = (1n << BITS) - 1n;
        inputs.message    = (BigInt(inputs.message)    & MASK).toString();
        inputs.randomness = (BigInt(inputs.randomness) & MASK).toString();
      }

      // 2) Bring encryption_key and encrypted_message into the same BN128 field
      if (inputs.encryption_key) {
        inputs.encryption_key = (BigInt(inputs.encryption_key) % CIRCOM_PRIME).toString();
      }
      if (inputs.encrypted_message) {
        inputs.encrypted_message = (BigInt(inputs.encrypted_message) % CIRCOM_PRIME).toString();
      }

      // 3) Call snarkjs to generate the proof
      const { proof: p, publicSignals: s } =
              await snarkjs[algorithm].fullProve(inputs, wasmPath, zkeyPath);
      return { success: true, proof: p, publicSignals: s };

    } else if (action === 'verify') {
      if (!cachedVKeys[vkeyPath]) {
        cachedVKeys[vkeyPath] = JSON.parse(await fs.readFile(vkeyPath, 'utf8'));
      }
      const vKey = cachedVKeys[vkeyPath];
      const ok   = await snarkjs[algorithm].verify(vKey, publicSignals, proof);
      return { success: true, isValid: ok };

    } else {
      throw new Error(`Unknown action: ${action}`);
    }

  } catch (err) {
    console.error('[Node Engine Error]', err);
    return { success: false, error: err.message };
  }
}

app.post('/zk', async (req, res) => {
  const out = await handleSnarkJsRequest(req.body);
  res.json(out);
});

app.post('/pedersen', async (req, res) => {
  try {
    const { message, randomness } = req.body;
    if (message === undefined || randomness === undefined) {
      return res.status(400).json({ success: false, error: 'Missing message or randomness' });
    }

    const pedersen = await circomlibjs.buildPedersenHash();
    const babyJub  = await circomlibjs.buildBabyjub();

    // Truncate to 248 bits
    const BITLEN  = 248n;
    const MASK    = (1n << BITLEN) - 1n;
    const msgBig  = BigInt(message)    & MASK;
    const randBig = BigInt(randomness) & MASK;

    // Pack into a little‐endian Buffer of 496 bits
    const totalBits  = Number(BITLEN * 2n);
    const totalBytes = Math.ceil(totalBits / 8);
    const buf        = Buffer.alloc(totalBytes, 0);

    // write message bits [0..247]
    for (let i = 0; i < Number(BITLEN); i++) {
      if ((msgBig >> BigInt(i)) & 1n) {
        buf[Math.floor(i / 8)] |= (1 << (i % 8));
      }
    }
    // write randomness bits [248..495]
    for (let i = 0; i < Number(BITLEN); i++) {
      if ((randBig >> BigInt(i)) & 1n) {
        const bitIndex = Number(BITLEN) + i;
        buf[Math.floor(bitIndex / 8)] |= (1 << (bitIndex % 8));
      }
    }

    const packed = pedersen.hash(buf);
    const point  = babyJub.unpackPoint(packed);

    res.json({
      success: true,
      commitment: [
        babyJub.F.toString(point[0]),
        babyJub.F.toString(point[1])
      ]
    });

  } catch (err) {
    console.error('[Pedersen Hash Error]', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, HOST, () => {
  console.log(`snarkjs server listening on http://${HOST}:${PORT}`);
});
