#!/usr/bin/env node
/**
 * hash-verify 已知答案测试（KAT）
 *
 * 用法：
 *   node test/kat.mjs [path/to/hash-verify.html]
 *
 * 参照实现（按可用性自动选择）：
 *   - MD5/SHA-1/SHA-224/SHA-256/SHA-384/SHA-512 : Node 内置 crypto
 *   - CRC32                                     : Node zlib.crc32
 *   - SHA3-256                                  : 系统 certutil（Windows，独立实现）+ FIPS 202 官方向量
 *   - BLAKE2b-512                               : RFC 7693 官方向量 + 本文件内的独立参考实现
 *
 * 退出码 0 表示全部通过。
 */
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const candidates = [
  process.argv[2],
  path.join(here, '..', 'index.html'),
  path.join(here, '..', 'hash-verify.html'),
  path.join(here, 'hash-verify.html')
].filter(Boolean);
const htmlPath = candidates.find((p) => fs.existsSync(p));
if (!htmlPath){
  console.error('找不到页面文件，请用 node test/kat.mjs <path/to/hash-verify.html> 指定。');
  process.exit(2);
}
const html = fs.readFileSync(htmlPath, 'utf8');
const m = html.match(/\/\* ===== HASH CORE START ===== \*\/([\s\S]*?)\/\* ===== HASH CORE END ===== \*\//);
if (!m){ console.error('未在页面中找到 HASH CORE 标记块。'); process.exit(2); }
const C = new Function(m[1] + `
;return { ALGORITHMS, ALGO_ORDER, LEN2ALGOS, createHasher, hashBytes, parseChecksumText,
          expectedHashes, bytesToHex, normName, baseName };`)();

let pass = 0, fail = 0;
const skips = [];
function eq(label, a, b){
  if (a === b) pass++;
  else { fail++; console.log('FAIL ' + label + '\n  got: ' + a + '\n  exp: ' + b); }
}
const u8 = (b) => new Uint8Array(b);
const enc = new TextEncoder();
const T = (label, algo, str, exp) => eq(label, C.hashBytes(algo, enc.encode(str)), exp);

/* ---------- 参照实现 ---------- */
const NODE_NAME = { md5:'md5', sha1:'sha1', sha224:'sha224', sha256:'sha256', sha384:'sha384', sha512:'sha512' };
const available = new Set(crypto.getHashes());
const usableLocal = ['md5','sha1','sha224','sha256','sha384','sha512'].filter((a) => available.has(NODE_NAME[a]));
if (Number(process.versions.node.split('.')[0]) < 20 || typeof zlib.crc32 !== 'function') skips.push('zlib.crc32');
else usableLocal.push('crc32');
const ref = (algo, buf) => algo === 'crc32'
  ? (zlib.crc32(buf) >>> 0).toString(16).padStart(8, '0')
  : crypto.createHash(NODE_NAME[algo]).update(buf).digest('hex');

/* BLAKE2b-512：与主实现结构不同的独立参考实现（显式切块 + 末块标志 + 字节计数器） */
function blake2bRef(msg, outLen = 64){
  const M = (1n << 64n) - 1n;
  const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M;
  const H = (s) => s.split(' ').map((x) => BigInt('0x' + x));
  const IV = H('6a09e667f3bcc908 bb67ae8584caa73b 3c6ef372fe94f82b a54ff53a5f1d36f1 510e527fade682d1 9b05688c2b3e6c1f 1f83d9abfb41bd6b 5be0cd19137e2179');
  const SIGMA = [
    [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15], [14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3],
    [11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4], [7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8],
    [9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13], [2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9],
    [12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11], [13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10],
    [6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5], [10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0]
  ];
  const h = IV.slice();
  h[0] ^= 0x01010000n ^ BigInt(outLen);
  const blocks = [];
  if (msg.length === 0) blocks.push(new Uint8Array(0));
  else for (let i = 0; i < msg.length; i += 128) blocks.push(msg.subarray(i, Math.min(i + 128, msg.length)));
  const v = new Array(16);
  let t = 0n;
  for (let bi = 0; bi < blocks.length; bi++){
    const blk = blocks[bi];
    t += BigInt(blk.length);
    const buf = new Uint8Array(128);
    buf.set(blk, 0);
    const mm = [];
    for (let i = 0; i < 16; i++){
      let w = 0n;
      for (let k = 0; k < 8; k++) w |= BigInt(buf[i * 8 + k]) << BigInt(8 * k);
      mm.push(w);
    }
    for (let i = 0; i < 8; i++){ v[i] = h[i]; v[i + 8] = IV[i]; }
    v[12] ^= t & M;
    v[13] ^= (t >> 64n) & M;
    if (bi === blocks.length - 1) v[14] ^= M;
    const G = (a, b, c, d, x, y) => {
      v[a] = (v[a] + v[b] + x) & M; v[d] = rotr(v[d] ^ v[a], 32n);
      v[c] = (v[c] + v[d]) & M;     v[b] = rotr(v[b] ^ v[c], 24n);
      v[a] = (v[a] + v[b] + y) & M; v[d] = rotr(v[d] ^ v[a], 16n);
      v[c] = (v[c] + v[d]) & M;     v[b] = rotr(v[b] ^ v[c], 63n);
    };
    for (let r = 0; r < 12; r++){
      const s = SIGMA[r % 10];
      G(0,4,8,12,mm[s[0]],mm[s[1]]);   G(1,5,9,13,mm[s[2]],mm[s[3]]);
      G(2,6,10,14,mm[s[4]],mm[s[5]]);  G(3,7,11,15,mm[s[6]],mm[s[7]]);
      G(0,5,10,15,mm[s[8]],mm[s[9]]);  G(1,6,11,12,mm[s[10]],mm[s[11]]);
      G(2,7,8,13,mm[s[12]],mm[s[13]]); G(3,4,9,14,mm[s[14]],mm[s[15]]);
    }
    for (let i = 0; i < 8; i++) h[i] = (h[i] ^ v[i] ^ v[i + 8]) & M;
  }
  let out = '';
  for (let i = 0; i < outLen; i++) out += ((h[i >> 3] >> BigInt(8 * (i & 7))) & 0xffn).toString(16).padStart(2, '0');
  return out;
}

/* SHA3-256：Windows certutil 作为独立参照（certutil 无法处理 0 字节文件） */
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'hashkat-'));
let certutilOk = true;
function certutilSha3(filePath){
  try {
    const out = execFileSync('certutil', ['-hashfile', filePath, 'SHA3-256'],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    const mm = out.match(/[0-9a-f]{64}/);
    return mm ? mm[0] : null;
  } catch (e){ certutilOk = false; return null; }
}

console.log('页面文件: ' + htmlPath);
console.log('\n=== 1) 官方已知答案向量 ===');
eq('MD5 ""', C.hashBytes('md5', new Uint8Array(0)), 'd41d8cd98f00b204e9800998ecf8427e');
T('MD5 abc', 'md5', 'abc', '900150983cd24fb0d6963f7d28e17f72');
T('MD5 The quick brown fox jumps over the lazy dog', 'md5', 'The quick brown fox jumps over the lazy dog', '9e107d9d372bb6826bd81d3542a419d6');
eq('SHA-1 ""', C.hashBytes('sha1', new Uint8Array(0)), 'da39a3ee5e6b4b0d3255bfef95601890afd80709');
T('SHA-1 abc', 'sha1', 'abc', 'a9993e364706816aba3e25717850c26c9cd0d89d');
T('SHA-1 448bit', 'sha1', 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '84983e441c3bd26ebaae4aa1f95129e5e54670f1');
T('SHA-224 abc', 'sha224', 'abc', '23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7');
eq('SHA-256 ""', C.hashBytes('sha256', new Uint8Array(0)), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
T('SHA-256 abc', 'sha256', 'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
T('SHA-384 abc', 'sha384', 'abc', 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7');
eq('SHA-512 ""', C.hashBytes('sha512', new Uint8Array(0)), 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e');
T('SHA-512 abc', 'sha512', 'abc', 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
eq('SHA3-256 ""', C.hashBytes('sha3_256', new Uint8Array(0)), 'a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a');
T('SHA3-256 abc', 'sha3_256', 'abc', '3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532');
T('SHA3-256 hello world', 'sha3_256', 'hello world', '644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938');
T('SHA3-256 quick brown fox', 'sha3_256', 'The quick brown fox jumps over the lazy dog', '69070dda01975c8c120c3aada1b282394e7f032fa9cf32f4cb2259a0897dfc04');
eq('BLAKE2b-512 ""', C.hashBytes('blake2b', new Uint8Array(0)), '786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce');
T('BLAKE2b-512 abc', 'blake2b', 'abc', 'ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923');
T('CRC32 123456789', 'crc32', '123456789', 'cbf43926');
eq('CRC32 ""', C.hashBytes('crc32', new Uint8Array(0)), '00000000');

console.log('=== 2) 与 Node crypto / zlib 对拍（长度 0..200 穷举 + 随机大块） ===');
console.log('    可用参照: ' + usableLocal.join(', '));
for (const algo of usableLocal){
  for (let n = 0; n <= 200; n++){
    const buf = crypto.randomBytes(n);
    eq(algo + ' n=' + n, C.hashBytes(algo, u8(buf)), ref(algo, buf));
  }
  for (const total of [1000, 4096, 65536, 200000]){
    const buf = crypto.randomBytes(total);
    eq(algo + ' big n=' + total, C.hashBytes(algo, u8(buf)), ref(algo, buf));
  }
}

console.log('=== 3) SHA3-256 对拍 certutil（独立参照，含多块与跨块边界） ===');
const sha3Sizes = [1, 3, 55, 100, 135, 136, 137, 200, 271, 272, 273, 500, 4096, 100000];
let certutilHits = 0;
for (const n of sha3Sizes){
  const buf = crypto.randomBytes(n);
  const p = path.join(tmp, 'f' + n + '.bin');
  fs.writeFileSync(p, buf);
  const want = certutilSha3(p);
  if (!want){ certutilOk = false; break; }
  certutilHits++;
  eq('SHA3-256 certutil n=' + n, C.hashBytes('sha3_256', u8(buf)), want);
}
if (!certutilOk){
  skips.push('certutil(SHA3-256 独立参照)');
  console.log('    跳过：本机 certutil 不支持 SHA3-256（FIPS 202 官方向量仍会验证）');
} else {
  console.log('    已用 certutil 校验 ' + certutilHits + ' 个尺寸');
}

console.log('=== 4) BLAKE2b-512 对拍独立参考实现 ===');
for (const total of [0, 1, 127, 128, 129, 255, 256, 257, 384, 1000, 4096, 100000]){
  const buf = crypto.randomBytes(total);
  eq('BLAKE2b-512 ref n=' + total, C.hashBytes('blake2b', u8(buf)), blake2bRef(u8(buf)));
}

console.log('=== 5) 分块流式喂入（随机块大小，全部算法） ===');
for (const algo of C.ALGO_ORDER){
  for (const total of [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 135, 136, 137, 272, 1000, 65536, 300000]){
    const buf = crypto.randomBytes(total);
    const h = C.createHasher(algo);
    let off = 0, seed = 987654321;
    const rnd = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
    while (off < total){
      const len = Math.min(total - off, 1 + Math.floor(rnd() * 900));
      h.update(u8(buf.subarray(off, off + len)));
      off += len;
    }
    eq(algo + ' chunked n=' + total, h.digestHex(), C.hashBytes(algo, u8(buf)));
  }
}

console.log('=== 6) 逐字节喂入（缓冲边界最极端情况） ===');
{
  const buf = crypto.randomBytes(6000);
  for (const algo of C.ALGO_ORDER){
    const h = C.createHasher(algo);
    for (let i = 0; i < buf.length; i++) h.update(u8(buf.subarray(i, i + 1)));
    eq(algo + ' byte-by-byte', h.digestHex(), C.hashBytes(algo, u8(buf)));
  }
}

console.log('=== 7) 算法注册表与校验清单解析器 ===');
eq('LEN2ALGOS 映射', JSON.stringify(C.LEN2ALGOS),
  JSON.stringify({ 8:['crc32'], 32:['md5'], 40:['sha1'], 56:['sha224'], 64:['sha256','sha3_256'], 96:['sha384'], 128:['sha512','blake2b'] }));
for (const a of C.ALGO_ORDER) eq(a + ' 输出长度', C.hashBytes(a, enc.encode('x')).length, C.ALGORITHMS[a].hexLen);

const h256 = 'd7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592';
const hmd5 = '9e107d9d372bb6826bd81d3542a419d6';
const h512 = '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909';
const h1 = 'a9993e364706816aba3e25717850c26c9cd0d89d';
const hcr = '352441c2';
const sample = [
  '# comment', '; another comment',
  h256 + '  app-windows-x64.exe',
  hmd5 + '  app-windows-x64.exe',
  h1 + ' *sub dir/other-file.zip',
  'SHA512 (third.bin) = ' + h512,
  'MD5 (third.bin) = ' + hmd5,
  hcr + '  small.cfg',
  'MD5 hash of file C:\\downloads\\setup.exe:',
  hmd5,
  'CertUtil: -hashfile command completed successfully.'
].join('\r\n');
const p = C.parseChecksumText(sample);
eq('解析条目数', p.entries.length, 7);
eq('无文件名条目数', p.generic.length, 0);
eq('无法识别行数', p.unparsed.length, 3);
eq('裸哈希视为通用期望值', C.parseChecksumText(h256).generic.length, 1);
eq('SHA-256 只取 64 位记录', JSON.stringify(C.expectedHashes(p, 'app-windows-x64.exe', 'sha256')), JSON.stringify([h256]));
eq('MD5 只取 32 位记录', JSON.stringify(C.expectedHashes(p, 'app-windows-x64.exe', 'md5')), JSON.stringify([hmd5]));
eq('CRC32 匹配', JSON.stringify(C.expectedHashes(p, 'small.cfg', 'crc32')), JSON.stringify([hcr]));
eq('SHA-512 按文件名匹配', JSON.stringify(C.expectedHashes(p, 'third.bin', 'sha512')), JSON.stringify([h512]));
eq('SHA-1 按文件名匹配', JSON.stringify(C.expectedHashes(p, 'other-file.zip', 'sha1')), JSON.stringify([h1]));
eq('certutil 输出解析', JSON.stringify(C.expectedHashes(p, 'setup.exe', 'md5')), JSON.stringify([hmd5]));
eq('64 位记录不匹配 128 位算法', JSON.stringify(C.expectedHashes(p, 'third.bin', 'sha256')), '[]');
eq('同长度歧义：SHA3-256 也认可 64 位记录', C.expectedHashes(p, 'app-windows-x64.exe', 'sha3_256').length, 1);
{
  const onlySha3 = C.parseChecksumText('SHA3-256 (x.bin) = ' + C.hashBytes('sha3_256', new Uint8Array()));
  eq('显式算法名不跨算法匹配', C.expectedHashes(onlySha3, 'x.bin', 'sha256').length, 0);
  eq('显式算法名自身匹配', C.expectedHashes(onlySha3, 'x.bin', 'sha3_256').length, 1);
}
eq('normName 归一化', C.normName('.\\Dir\\File.EXE'), 'dir/file.exe');
eq('baseName 取文件名', C.baseName('C:\\a\\b\\c.bin'), 'c.bin');

try { fs.rmSync(tmp, { recursive: true, force: true }); } catch (e){}

if (skips.length) console.log('\n已跳过: ' + skips.join(', '));
console.log('\n结果: pass=' + pass + ' fail=' + fail);
process.exit(fail ? 1 : 0);
