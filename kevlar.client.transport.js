// Kevlar transport module | Spencer Tipping
// Licensed under the terms of the MIT source code license

// Introduction.
// Most web servers will want to provide some kind of content protection. Sometimes this happens using HTTPS, but that may or may not be necessary depending on the application. I'm implementing
// these encryption and hashing functions to provide a non-HTTPS way to do most authentication-related stuff with reasonable security. (I'm also aware that these libraries are available
// elsewhere, but I'm reimplementing stuff here for fun. It's fine with me if you want to fork the project to use existing open-source solutions instead of my less-performant versions.)

  caterwaul.js_all()(function () {

// Ascii85 encoding.
// This is similar to base-64 but achieves a better packing ratio. The idea is to take each 32-bit group of characters (in this case two characters, since a character has 16 bits and I'm too lazy
// to do UTF-8 encoding) and arithmetically convert that into five base-85 digits. Each base-85 digit is just ASCII 33 + some number, yielding a high value of 127. This encoder doesn't insert
// checksums or add metadata other than the minimal amount of padding necessary to derive the length of the original string. This implementation differs from the one described at
// http://en.wikipedia.org/wiki/Ascii85 in that it adds at most one null character, since each character is encoded as 16 bits rather than 8.

  kevlar -effect [
    it.encode85(s) = encoded -where [encode_block(n) = n[5] *[String.fromCharCode(33 + n / powers_of_85[4 - x] % 85)] -seq -re- it.join(''),
                                     padded          = s.length & 1 ? s + String.fromCharCode(0) : s,
                                     encoded_string  = n[0, padded.length, 2] *[encode_block((padded.charCodeAt(x) << 16 | padded.charCodeAt(x + 1)) >>> 0)] -seq -re- it.join(''),
                                     encoded         = s.length & 1 ? encoded_string.substr(0, encoded_string.length - 2) : encoded_string],

    it.decode85(s) = decoded -where [decode_block(n) = String.fromCharCode(n >>> 16) + String.fromCharCode(n >>> 0 & 0xffff),
                                     block_value(s)  = n[6] /[x * 85 + s.charCodeAt(x0 - 1) - 33] -seq,
                                     padded          = s.length % 5 ? '#{s}uu' : s,
                                     decoded_string  = n[0, padded.length, 5] *[decode_block(block_value(padded.substr(x, 5)))] -seq -re- it.join(''),
                                     decoded         = s.length % 5 ? decoded_string.substr(0, decoded_string.length - 1) : decoded_string],

    where [powers_of_85 = n[5] *~[n[1, x + 2] /[x * 85]] -seq]],

// SHA-256 hashing.
// This is used to sign messages going back and forth, and for password challenges. It's a fairly standard implementation that returns its internal state as a big-endian string of data; my
// intention is to use it in conjunction with the above ascii-85 encoder to provide message digests. The constants and algorithm are from the pseudocode at http://en.wikipedia.org/wiki/SHA-256.

// Like the other functions in this file, this function treats all characters as being of 16-bit constant width. This results in some of the numbers being different from usual, and all of the
// hashes will be different from the same hash on ASCII-encoded text.

  kevlar -effect [
    it.sha256(s) = n[0, p.length, 32] *![h = hash_block(h, p.substr(x, 32))] -seq
                   -re- h *[String.fromCharCode(x >>> 16) + String.fromCharCode(x & 0xffff)] /seq -re- it.join('') -where [h = hs.slice(), p = pad(s)],

    where [hs = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19],
           ks = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
                 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
                 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],

           rr(x, bits)       = x >>> bits | x << 32 - bits,
           hash_block(hs, s) = nhs -where [ws  = n[0, 32, 2] *[s.charCodeAt(x) << 16 | s.charCodeAt(x + 1)] -seq -effect-
                                                 n[16, 64]  *![it[x] = it[x - 16] + s0 + it[x - 7] + s1 >>> 0, where [s0 = rr(it[x - 15], 7) ^ rr(it[x - 15], 18) ^ it[x - 15] >>> 3,
                                                                                                                      s1 = rr(it[x - 2], 17) ^ rr(it[x - 2],  19) ^ it[x - 2]  >>> 10]] /seq,

                                           nhs = bind [a = hs[0], b = hs[1], c = hs[2], d = hs[3], e = hs[4], f = hs[5], g = hs[6], h = hs[7]] in
                                                 n[64] *![h = g, g = f, f = e, e = d + t1 >>> 0, d = c, c = b, b = a, a = t1 + t2 >>> 0,
                                                          where [t1 = ks[x] + ws[x] + h + (rr(e, 6) ^ rr(e, 11) ^ rr(e, 25)) + (e & f ^ ~e & g) >>> 0,
                                                                 t2 = (rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + (a & b ^ a & c ^ b & c) >>> 0]] -seq
                                                 -re- [a, b, c, d, e, f, g, h] *[hs[xi] + x >>> 0] /seq],

//   Length calculation.
//   The SHA-256 spec says that we pad the source out to be 448 bits mod 512, then append the 64-bit big-endian length in bits. The padding is a 1 followed by 0 bits. Because this implementation
//   uses 16-bit characters, the numbers become 448 / 16 = 28 and 64 / 16 = 4. So we pad out to 28 characters, then add the length to total 32 characters (512 bits).

           pad(s)                = s + String.fromCharCode(0x8000) + padding_characters((28 + 32 - (s.length + 1) % 32) % 32) + big_endian_64(s.length * 16),
           padding_characters(n) = n[n] *[String.fromCharCode(0)] -seq -re- it.join(''),
           big_endian_64(n)      = [0, 0, n >>> 16, n & 0xffff] *[String.fromCharCode(x)] -seq -re- it.join('')]],

// HMAC.
// Combined with SHA-256 above, HMAC is used to securely sign a message with little possibility of forgery or key retrieval. (http://en.wikipedia.org/wiki/HMAC has more details.) This algorithm
// unconditionally hashes the salt (not per the official spec, but this is simpler) and returns the final hash. My key derivation function isn't nearly as rigorous as PBKDF2; once I understand
// the security risks more completely I may change it.

  kevlar -effect [
    it.derive_key(password) = n[1000] /[it.sha256(x0 || password)] -seq,
    it.hmac(k, s) = hash(ok + hash(ik + s)) -where [hash = it.sha256, kp = hash(k), ik = n[16] *[String.fromCharCode(kp.charCodeAt(x) ^ 0x5c)] -seq -re- it.join(''),
                                                                                    ok = n[16] *[String.fromCharCode(kp.charCodeAt(x) ^ 0x36)] -seq -re- it.join('')]],

// High-level signature of JSON data.
// Any JSON object can be signed and independently verified by the server. This is done by generating a signature function that will then wrap your values appropriately. A wrapped value looks
// like this:

// | {username: 'foo', message: 'plaintext message', signature: 'base85-signature'}

// The signature generator automatically JSON-encodes the message to be sent. The verifier automatically JSON-decodes into an object, or returns undefined if the message didn't have a valid
// signature.

  kevlar -effect [
    it.signature_verifier(derived_keys)(message)       = it.decode85(message.signature) === it.hmac(derived_keys[message.user], message.message) ? JSON.parse(message.message) : undefined,
    it.signature_generator(username, derived)(message) = {user: username, message: text, signature: it.encode85(it.hmac(derived, text))} -where [text = JSON.stringify(message)]]})();

// Generated by SDoc 
