/**
 * -----------------------------------------------------------------------------
 * Project: Fossil Logic
 *
 * This file is part of the Fossil Logic project, which aims to develop
 * high-performance, cross-platform applications and libraries. The code
 * contained herein is licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain
 * a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 * Author: Michael Gene Brockus (Dreamer)
 * Date: 04/05/2014
 *
 * Copyright (C) 2014-2025 Fossil Logic. All rights reserved.
 * -----------------------------------------------------------------------------
 */
#include "fossil/ai/jellyfish.h"

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#include <wincrypt.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/time.h>
#endif

/* ------------------------------------------------------------------
 * Portable strnlen fallback (POSIX function may be missing on some
 * older C libraries / MSVC prior to VS2015).
 * ------------------------------------------------------------------ */
#ifndef FOSSIL_JELLYFISH_STRNLEN_FALLBACK_H
#define FOSSIL_JELLYFISH_STRNLEN_FALLBACK_H
#include <stddef.h>
static size_t fossil_jellyfish_strnlen_fallback(const char *s, size_t maxlen) {
    if (!s) return 0;
    size_t i = 0;
    while (i < maxlen && s[i] != '\0') ++i;
    return i;
}
#if !defined(strnlen)
/* Map strnlen calls in this translation unit to the fallback if the
 * system one is not available. */
#define strnlen(s, n) fossil_jellyfish_strnlen_fallback((s), (n))
#endif
#endif

// ========================================================
// HASH Algorithm magic
// ========================================================

/**
 * Jellyfish Hash & Utility Module Overview
 *
 * This module provides:
 *   1. 64-bit bit rotation macros (ROTL64 / ROTR64) for endian-agnostic,
 *      constant-time circular shifts used to induce diffusion and avalanche
 *      in state mixing.
 *   2. Cross-platform microsecond timer (get_time_microseconds) to introduce
 *      temporal entropy (nonce-like variability) into hashing.
 *   3. A device / environment–derived 64-bit salt (get_device_salt) that
 *      attempts high-entropy initialization via:
 *         - OS cryptographic provider (Windows CryptGenRandom)
 *         - /dev/urandom (POSIX)
 *         - Fallback hashing of selected environment variables (low entropy)
 *      The salt is cached statically to avoid recomputation.
 *   4. A static 256-byte substitution box (SBOX), currently using the classic
 *      AES S-box values, employed as a nonlinear layer in several mixing paths.
 *   5. A multiplicative inverse routine over the finite field defined modulo
 *      the prime 257 (modinv) — treating bytes in (0..255) as elements whose
 *      inverses exist except 0 (for which a conventional 0 mapping is returned).
 *      This is analogous to the algebraic step in AES S-box construction but
 *      uses mod 257 arithmetic instead of GF(2^8) polynomial basis; the code
 *      enables dynamic S-box regeneration for experimentation.
 *   6. An affine transform (affine_transform) applying a 3-bit left rotate
 *      plus XOR with 0x63 to introduce structured nonlinearity (mirroring
 *      style of AES final affine layer while not identical in field semantics).
 *   7. A S-box generation utility (generate_sbox) that:
 *         - Fixes index 0 to 0x63 (paralleling AES S-box convention where
 *           the inverse of 0 is mapped deliberately).
 *         - For each nonzero byte: computes modular inverse (mod 257) then
 *           applies the affine transform.
 *      NOTE: The compiled-in static SBOX is used directly; this function
 *            enables runtime derivation for research or variant designs.
 *   8. The primary custom hash routine (fossil_ai_jellyfish_hash) producing
 *      a variable-length (externally defined size via FOSSIL_JELLYFISH_HASH_SIZE)
 *      byte digest from two input C strings (input, output) plus internal
 *      entropy sources (device salt + time nonce).
 *
 * Hash Algorithm Structure (fossil_ai_jellyfish_hash):
 *   - Initialization:
 *       state1 / state2 seeded with FNV-1 style 64-bit offset basis values
 *       XORed with the static SALT and its bitwise negation to decorrelate
 *       parallel lanes.
 *       A 64-bit microsecond timestamp (nonce) is captured to inject temporal
 *       variability (non-deterministic across runs).
 *   - Input Mixing Phase:
 *       For each position i in the first string:
 *         * A pseudo-permuted index j = (i * 17 + 31) mod len introduces
 *           stride-based reordering.
 *         * Byte -> SBOX nonlinear lookup.
 *         * Combined with state1 via XOR, ROTL64, self-XOR-shift, and
 *           multiplicative mixing with PRIME (0x100000001b3, the 64-bit FNV prime).
 *   - Output Mixing Phase:
 *       Mirrors input phase but uses a different linear congruential stride
 *       (i * 11 + 19) and right rotations (ROTR64) to create asymmetry
 *       between the two string roles.
 *   - Block Compression:
 *       Walks 8-byte aligned chunks of the first string:
 *         * Loads a 64-bit chunk (unaligned-friendly via memcpy semantics).
 *         * Injects a byte-dependent SBOX feedback into the high byte.
 *         * Applies alternating left / right rotational and multiplicative
 *           diffusion between h1 and h2, chaining them to cross-contaminate
 *           entropy.
 *   - Final State Folding:
 *       Lengths, nonce, and cross-rotated versions of the complementary
 *       state are XORed in to prevent length-extension style trivialities.
 *   - Dynamic Avalanche Rounds:
 *       6–9 rounds (nonce % 4 variability) of:
 *         * Dependent rotations with indices modulated by round number
 *         * Cross-lane XOR feedback
 *         * Multiplicative scrambling by PRIME
 *       This stage aims to decorrelate near-collisions and amplify bit flips.
 *   - Digest Whitening & Extraction:
 *       A rolling 64-bit digest is iteratively:
 *         * XORed with SBOX-masked byte slices of itself
 *         * Rotated with variable offsets
 *         * Multiplied by PRIME
 *       Each iteration yields one output byte (indexing per (i % 8) window),
 *       continuing until FOSSIL_JELLYFISH_HASH_SIZE bytes are emitted.
 *
 * CRC32 Support:
 *   - A standard 256-entry CRC32 lookup table (polynomial 0xEDB88320) enables
 *     fast computation of CRC32 checksums over arbitrary byte sequences via
 *     crc32(). This is a distinct utility: CRC32 is NOT part of the hash digest
 *     pipeline above but may be used for integrity verification or secondary
 *     tagging.
 *
 * Security & Cryptographic Caveats:
 *   - This hash is NOT a proven cryptographic construction. It lacks formal
 *     analysis for:
 *        * Collision resistance
 *        * Preimage resistance
 *        * Differential / rotational attacks
 *        * Timing / side-channel behavior (data-dependent table lookups)
 *   - Use only for:
 *        * Non-cryptographic fingerprinting
 *        * Heuristic bucketing
 *        * Obfuscation where strong adversaries are not a concern
 *   - Do NOT use for:
 *        * Password hashing
 *        * Digital signatures / MACs
 *        * Cryptographic key derivation
 *   - SBOX lookups may leak access patterns via cache timing (avoid in
 *     sensitive contexts).
 *   - Entropy sources (environment variables, timestamp) are not substitutes
 *     for cryptographically secure randomness.
 *
 * Portability Notes:
 *   - Assumes little-endian friendly behavior for byte extraction from
 *     rotating 64-bit digest (but logic itself is endian-agnostic since
 *     shifts are defined on integers, and byte selection masks explicitly).
 *   - Uses <windows.h> and Crypt* APIs on Windows; /dev/urandom + POSIX I/O
 *     elsewhere. Ensure proper includes for open/read/close if compiled
 *     separately (fcntl.h / unistd.h).
 *
 * Performance Characteristics:
 *   - Dominant cost: SBOX-indexing + rotation-heavy arithmetic
 *   - O(n) in combined input/output lengths
 *   - Limited working set (fits in L1), predictable branch profile
 *
 * Extensibility Ideas:
 *   - Replace AES SBOX with runtime-generated variant (call generate_sbox)
 *     for polymorphic builds.
 *   - Introduce keyed mode: XOR a secret key into initial states and/or
 *     affine layer to approximate a MAC-like function (still not formally secure).
 *   - Increase avalanche rounds or adopt a permutation schedule keyed by
 *     SALT bits to diversify builds.
 *   - Replace PRIME with a set of co-prime rotational multipliers rotated per round.
 *
 * Safety Considerations:
 *   - Expects valid null-terminated C strings for 'input' and 'output'.
 *   - Caller must provide a hash_out buffer of at least FOSSIL_JELLYFISH_HASH_SIZE bytes.
 *   - FOSSIL_JELLYFISH_HASH_SIZE must be defined (likely in a shared header).
 *
 * Summary:
 *   This file aggregates a custom experimental hash (Jellyfish) blending
 *   classic FNV-like multiplicative diffusion, AES-inspired S-box nonlinear
 *   layers, time + device salting, and adaptive avalanche rounds. It also
 *   furnishes a canonical CRC32 utility for orthogonal integrity use cases.
 *   Treat all cryptographic properties as UNVERIFIED; deploy only where
 *   non-adversarial robustness is acceptable.
 */

#define ROTL64(x, r) (((x) << (r)) | ((x) >> (64 - (r))))
#define ROTR64(x, r) (((x) >> (r)) | ((x) << (64 - (r))))

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
uint64_t get_time_microseconds(void) {
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    uint64_t t = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    return t / 10; // 100-nanosecond intervals to microseconds
}
#else
#include <sys/time.h>
uint64_t get_time_microseconds(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}
#endif

static uint64_t get_device_salt(void) {
    uint64_t hash = 0xcbf29ce484222325ULL;

    // Try system randomness first
#if defined(_WIN32) || defined(_WIN64)
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, sizeof(hash), (BYTE*)&hash);
        CryptReleaseContext(hProv, 0);
        return hash;
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, &hash, sizeof(hash)) == sizeof(hash)) {
            close(fd);
            return hash;
        }
        close(fd);
    }
#endif

    // Fallback: environment variables
#if defined(_WIN32) || defined(_WIN64)
    const char *vars[] = { getenv("USERNAME"), getenv("USERPROFILE"), getenv("COMPUTERNAME") };
#else
    const char *vars[] = { getenv("USER"), getenv("HOME"), getenv("SHELL"), getenv("HOSTNAME") };
#endif

    for (size_t v = 0; v < sizeof(vars) / sizeof(vars[0]); ++v) {
        const char *val = vars[v];
        if (val) {
            for (size_t i = 0; val[i]; ++i) {
                hash ^= (uint8_t)val[i];
                hash *= 0x100000001b3ULL;
            }
        }
    }

    return hash;
}

static const uint8_t SBOX[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

// Compute multiplicative inverse mod 257 (prime just above 256)
static uint8_t modinv(uint8_t x) {
    int a = x, m = 257, m0 = m;
    int y = 0, x0 = 1;

    if (x == 0) return 0; // define inverse(0) = 0

    while (a > 1) {
        int q = a / m;
        int t = m;
        m = a % m; a = t;
        t = y;
        y = x0 - q * y;
        x0 = t;
    }

    if (x0 < 0) x0 += m0;
    return (uint8_t)x0;
}

// Simple affine transform (rotate left 3 + XOR 0x63)
static uint8_t affine_transform(uint8_t x) {
    return ((x << 3) | (x >> 5)) ^ 0x63;
}

// Generate and print S-box table
void generate_sbox(uint8_t sbox[256]) {
    sbox[0] = 0x63; // fixed value for zero input (like AES)
    for (int i = 1; i < 256; ++i) {
        uint8_t inv = modinv((uint8_t)i);
        sbox[i] = affine_transform(inv);
    }
}

void fossil_ai_jellyfish_hash(const char *input, const char *output, uint8_t *hash_out) {
    const uint64_t PRIME = 0x100000001b3ULL;
    static uint64_t SALT = 0;
    if (SALT == 0) SALT = get_device_salt();

    uint64_t state1 = 0xcbf29ce484222325ULL ^ SALT;
    uint64_t state2 = 0x84222325cbf29ce4ULL ^ ~SALT;
    uint64_t nonce = get_time_microseconds();

    size_t in_len = strlen(input);
    size_t out_len = strlen(output);

    // Input mixing using SBOX and ROTL
    for (size_t i = 0; i < in_len; ++i) {
        size_t j = (i * 17 + 31) % in_len;
        uint8_t c = (uint8_t)input[j];
        uint8_t s = SBOX[c];
        state1 ^= ROTL64(s ^ state1, 13);
        state1 = ROTL64(state1 ^ (state1 >> 7), 31) * PRIME;
    }

    // Output mixing using SBOX and ROTR
    for (size_t i = 0; i < out_len; ++i) {
        size_t j = (i * 11 + 19) % out_len;
        uint8_t c = (uint8_t)output[j];
        uint8_t s = SBOX[c];
        state2 ^= ROTR64(s ^ state2, 11);
        state2 = ROTR64(state2 ^ (state2 >> 5), 29) * PRIME;
    }

    // Chunk compression: 8-byte blocks with SBOX feedback
    uint64_t h1 = state1, h2 = state2;
    for (size_t i = 0; i + 8 <= in_len; i += 8) {
        uint64_t chunk = 0;
        memcpy(&chunk, &input[i], 8);
        chunk ^= (uint64_t)SBOX[input[i] & 0xFF] << 56;
        h1 ^= chunk;
        h1 = ROTL64(h1, 23) * PRIME;
        h2 ^= h1;
        h2 = ROTR64(h2, 17) * PRIME;
    }

    // Final mixing with nonce and lengths
    h1 ^= nonce ^ ((uint64_t)in_len << 32) ^ (ROTL64(state2, 11));
    h2 ^= ~nonce ^ ((uint64_t)out_len << 16) ^ (ROTR64(state1, 7));

    // Dynamic avalanche rounds
    int rounds = 6 + (nonce % 4);
    for (int i = 0; i < rounds; ++i) {
        h1 += ROTL64(h2 ^ (h1 >> 17), (i % 29) + 5);
        h2 += ROTR64(h1 ^ (h2 >> 13), (i % 31) + 3);
        h1 ^= ROTL64(h1, 41 - (i % 7));
        h2 ^= ROTR64(h2, 37 - (i % 5));
        h1 *= PRIME;
        h2 *= PRIME;
    }

    // Final digest whitening with SBOX and rotation
    uint64_t digest = h1 ^ h2 ^ SALT ^ nonce;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_HASH_SIZE; ++i) {
        uint8_t s = SBOX[(digest >> (i % 8)) & 0xFF];
        digest ^= ((uint64_t)s << (8 * (i % 8)));
        digest = ROTL64(digest, 13 + (i % 5)) * PRIME;
        hash_out[i] = (uint8_t)((digest >> (8 * (i % 8))) & 0xFF);
    }
}

// CRC magic

static const uint32_t crc32_table[256] = {
    0x00000000L, 0x77073096L, 0xee0e612cL, 0x990951baL,
    0x076dc419L, 0x706af48fL, 0xe963a535L, 0x9e6495a3L,
    0x0edb8832L, 0x79dcb8a4L, 0xe0d5e91eL, 0x97d2d988L,
    0x09b64c2bL, 0x7eb17cbdL, 0xe7b82d07L, 0x90bf1d91L,
    0x1db71064L, 0x6ab020f2L, 0xf3b97148L, 0x84be41deL,
    0x1adad47dL, 0x6ddde4ebL, 0xf4d4b551L, 0x83d385c7L,
    0x136c9856L, 0x646ba8c0L, 0xfd62f97aL, 0x8a65c9ecL,
    0x14015c4fL, 0x63066cd9L, 0xfa0f3d63L, 0x8d080df5L,
    0x3b6e20c8L, 0x4c69105eL, 0xd56041e4L, 0xa2677172L,
    0x3c03e4d1L, 0x4b04d447L, 0xd20d85fdL, 0xa50ab56bL,
    0x35b5a8faL, 0x42b2986cL, 0xdbbbc9d6L, 0xacbcf940L,
    0x32d86ce3L, 0x45df5c75L, 0xdcd60dcfL, 0xabd13d59L,
    0x26d930acL, 0x51de003aL, 0xc8d75180L, 0xbfd06116L,
    0x21b4f4b5L, 0x56b3c423L, 0xcfba9599L, 0xb8bda50fL,
    0x2802b89eL, 0x5f058808L, 0xc60cd9b2L, 0xb10be924L,
    0x2f6f7c87L, 0x58684c11L, 0xc1611dabL, 0xb6662d3dL,
    0x76dc4190L, 0x01db7106L, 0x98d220bcL, 0xefd5102aL,
    0x71b18589L, 0x06b6b51fL, 0x9fbfe4a5L, 0xe8b8d433L,
    0x7807c9a2L, 0x0f00f934L, 0x9609a88eL, 0xe10e9818L,
    0x7f6a0dbbL, 0x086d3d2dL, 0x91646c97L, 0xe6635c01L,
    0x6b6b51f4L, 0x1c6c6162L, 0x856530d8L, 0xf262004eL,
    0x6c0695edL, 0x1b01a57bL, 0x8208f4c1L, 0xf50fc457L,
    0x65b0d9c6L, 0x12b7e950L, 0x8bbeb8eaL, 0xfcb9887cL,
    0x62dd1ddfL, 0x15da2d49L, 0x8cd37cf3L, 0xfbd44c65L,
    0x4db26158L, 0x3ab551ceL, 0xa3bc0074L, 0xd4bb30e2L,
    0x4adfa541L, 0x3dd895d7L, 0xa4d1c46dL, 0xd3d6f4fbL,
    0x4369e96aL, 0x346ed9fcL, 0xad678846L, 0xda60b8d0L,
    0x44042d73L, 0x33031de5L, 0xaa0a4c5fL, 0xdd0d7cc9L,
    0x5005713cL, 0x270241aaL, 0xbe0b1010L, 0xc90c2086L,
    0x5768b525L, 0x206f85b3L, 0xb966d409L, 0xce61e49fL,
    0x5edef90eL, 0x29d9c998L, 0xb0d09822L, 0xc7d7a8b4L,
    0x59b33d17L, 0x2eb40d81L, 0xb7bd5c3bL, 0xc0ba6cadL,
    0xedb88320L, 0x9abfb3b6L, 0x03b6e20cL, 0x74b1d29aL,
    0xead54739L, 0x9dd277afL, 0x04db2615L, 0x73dc1683L,
    0xe3630b12L, 0x94643b84L, 0x0d6d6a3eL, 0x7a6a5aa8L,
    0xe40ecf0bL, 0x9309ff9dL, 0x0a00ae27L, 0x7d079eb1L,
    0xf00f9344L, 0x8708a3d2L, 0x1e01f268L, 0x6906c2feL,
    0xf762575dL, 0x806567cbL, 0x196c3671L, 0x6e6b06e7L,
    0xfed41b76L, 0x89d32be0L, 0x10da7a5aL, 0x67dd4accL,
    0xf9b9df6fL, 0x8ebeeff9L, 0x17b7be43L, 0x60b08ed5L,
    0xd6d6a3e8L, 0xa1d1937eL, 0x38d8c2c4L, 0x4fdff252L,
    0xd1bb67f1L, 0xa6bc5767L, 0x3fb506ddL, 0x48b2364bL,
    0xd80d2bdaL, 0xaf0a1b4cL, 0x36034af6L, 0x41047a60L,
    0xdf60efc3L, 0xa867df55L, 0x316e8eefL, 0x4669be79L,
    0xcb61b38cL, 0xbc66831aL, 0x256fd2a0L, 0x5268e236L,
    0xcc0c7795L, 0xbb0b4703L, 0x220216b9L, 0x5505262fL,
    0xc5ba3bbeL, 0xb2bd0b28L, 0x2bb45a92L, 0x5cb36a04L,
    0xc2d7ffa7L, 0xb5d0cf31L, 0x2cd99e8bL, 0x5bdeae1dL,
    0x9b64c2b0L, 0xec63f226L, 0x756aa39cL, 0x026d930aL,
    0x9c0906a9L, 0xeb0e363fL, 0x72076785L, 0x05005713L,
    0x95bf4a82L, 0xe2b87a14L, 0x7bb12baeL, 0x0cb61b38L,
    0x92d28e9bL, 0xe5d5be0dL, 0x7cdcefb7L, 0x0bdbdf21L,
    0x86d3d2d4L, 0xf1d4e242L, 0x68ddb3f8L, 0x1fda836eL,
    0x81be16cdL, 0xf6b9265bL, 0x6fb077e1L, 0x18b74777L,
    0x88085ae6L, 0xff0f6a70L, 0x66063bcaL, 0x11010b5cL,
    0x8f659effL, 0xf862ae69L, 0x616bffd3L, 0x166ccf45L,
    0xa00ae278L, 0xd70dd2eeL, 0x4e048354L, 0x3903b3c2L,
    0xa7672661L, 0xd06016f7L, 0x4969474dL, 0x3e6e77dbL,
    0xaed16a4aL, 0xd9d65adcL, 0x40df0b66L, 0x37d83bf0L,
    0xa9bcae53L, 0xdebb9ec5L, 0x47b2cf7fL, 0x30b5ffe9L,
    0xbdbdf21cL, 0xcabac28aL, 0x53b39330L, 0x24b4a3a6L,
    0xbad03605L, 0xcdd70693L, 0x54de5729L, 0x23d967bfL,
    0xb3667a2eL, 0xc4614ab8L, 0x5d681b02L, 0x2a6f2b94L,
    0xb40bbe37L, 0xc30c8ea1L, 0x5a05df1bL, 0x2d02ef8dL
};

uint32_t crc32(const uint8_t *data, size_t length) {
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < length; i++) {
        crc = (crc >> 8) ^ crc32_table[(crc ^ data[i]) & 0xFF];
    }
    return crc ^ 0xFFFFFFFFu;
}

// ======================================================================
// Source implmentation
// ======================================================================

/*
 * -----------------------------------------------------------------------------
 * Jellyfish Chain Core API – Internal Operational Overview
 * (Covers the cluster of functions immediately following this block:
 *  init / learn / remove / find / update / save / load / maintenance /
 *  reasoning / verification / pruning / stats helpers, etc.)
 *
 * DATA MODEL (fossil_ai_jellyfish_chain_t)
 * ---------------------------------------
 *  - Fixed-capacity array (FOSSIL_JELLYFISH_MAX_MEM) of commit “blocks”.
 *  - Each block (fossil_ai_jellyfish_block_t) is a content–addressed
 *    record (commit_hash) built from input/output text plus ancestry /
 *    decoration mixing. Tree hash presently mirrors commit hash.
 *  - Lightweight “FSON” sub-structures (semantic_meta, audit_meta, io_meta,
 *    root, attachments) give a JSON‑like extensible metadata layer without
 *    pulling in a full JSON library.
 *  - Branch vector holds named heads (no DAG traversal utilities here;
 *    chains are scanned linearly—acceptable for bounded memory).
 *
 * LIFECYCLE FUNCTIONS
 * -------------------
 *  fossil_ai_jellyfish_init:
 *    - Zeroes the entire chain (memset) – safe because we immediately
 *      reconstruct required OBJECT roots for repo_meta and branch_meta.
 *    - Sets timestamps (created_at / updated_at) to a microsecond clock.
 *    - Seeds repo_id with a salted/time‑mixed 64-bit entropy source for
 *      pseudo-identity (NOT cryptographic uniqueness).
 *    - Pre-initializes every commit slot with neutral state and assigns
 *      a commit_index (stable slot index even while invalid).
 *
 *  fossil_ai_jellyfish_learn:
 *    - Appends or reuses the first invalid slot (soft reuse / lazy GC).
 *    - Copies bounded input/output strings; derives lengths and tokenizes
 *      into fixed arrays (lowercased alphanumeric segmentation).
 *    - Computes commit hash (content address) and mirrors into tree_hash.
 *    - Initializes classification & metadata FSON roots as empty OBJECTs.
 *    - Seeds starting confidence (0.75 heuristic) and timestamps.
 *    - Updates default branch head (slot 0 branch) to new hash.
 *
 *  fossil_ai_jellyfish_remove:
 *    - Logical invalidate: clears validity, marks pruned, zeroes confidence,
 *      stamps expires_at (no physical compaction here).
 *
 *  fossil_ai_jellyfish_find / _get / _find_by_hash:
 *    - Linear scans over bounded array; acceptable due to fixed upper size.
 *    - _find_by_hash returns first valid block whose commit hash matches.
 *
 *  fossil_ai_jellyfish_update:
 *    - In-place mutation of input/output (if mutable + valid).
 *    - Re-tokenizes, re-hashes, upgrades INFER -> PATCH (evolution rule).
 *    - Applies mild confidence decay + small reinforcement to reflect edit.
 *    - Propagates new commit hash to any branch head that referenced the old.
 *
 * PERSISTENCE
 * -----------
 *  fossil_ai_jellyfish_save / _load:
 *    - Binary snapshot with a small header (magic, version, counts, repo id).
 *    - Only valid blocks are serialized; commit_capacity & commit_count
 *      retained to reconstruct sparse occupancy.
 *    - FSON dynamic trees beyond core OBJECT scaffolds are NOT serialized
 *      here (current implementation only reinitializes empty OBJECT shells).
 *    - attr_flags packs multiple boolean attributes into a byte.
 *    - Loading rebuilds base structure, reinstates hashes, attributes, IO,
 *      but semantic/audit detail beyond simple OBJECT roots is empty unless
 *      expanded by a higher-level export layer later.
 *
 * MAINTENANCE & HYGIENE
 * ---------------------
 *  fossil_ai_jellyfish_cleanup:
 *    - Sweeps every slot: enforces bounds, expires timed-out blocks,
 *      clamps token/parent counts, normalizes merge flags, shrinks
 *      chain->count logically to highest valid+1 (no reordering).
 *    - Sanitizes branch heads (zeroes stale references).
 *
 *  fossil_ai_jellyfish_prune / _trim / _deduplicate / _compress_chain:
 *    - prune: invalidates blocks below a confidence threshold or expired.
 *    - trim: retains highest “value” subset (confidence + recency heuristic),
 *      removing lowest-ranked mutable blocks until max_blocks satisfied.
 *    - deduplicate: removes later duplicates (same input+output) preferring
 *      higher confidence / earlier timestamp.
 *    - compress_chain: whitespace normalization + retokenization +
 *      marks compressed/compressed flags; recomputation of lengths.
 *
 *  fossil_ai_jellyfish_chain_compact:
 *    - Physically packs valid blocks toward front preserving order;
 *      reassigns indices; zeroes trailing slots (optional memory hygiene).
 *
 * REASONING & QUERY
 * -----------------
 *  fossil_ai_jellyfish_reason / _reason_verbose / _best_match:
 *    - Token-based approximate retrieval (Jaccard overlap) with fresher
 *      and more confident blocks weighted higher.
 *    - Exact input match short-circuits to highest sentinel score.
 *    - Verbose variant surfaces confidence + pointer to winning block.
 *    - Lightweight reinforcement loop increments usage_count and nudges
 *      confidence upward (bounded).
 *
 * ANALYSIS / VERIFICATION
 * -----------------------
 *  fossil_ai_jellyfish_audit:
 *    - Multi-criterion anomaly counter (hash mismatch, invalid parents,
 *      merge flag inconsistencies, length mismatches, signature rules).
 *  fossil_ai_jellyfish_verify_chain / _verify_block:
 *    - Strict boolean validation (early exit on first failure) suitable
 *      for integrity gates before persistence or replication.
 *  fossil_ai_jellyfish_chain_trust_score:
 *    - Weighted average factoring confidence, usage (log2 scaled),
 *      trust, immutability, block type semantics, and penalties for
 *      redacted / conflicted states.
 *  fossil_ai_jellyfish_chain_fingerprint:
 *    - Order-independent accumulation over commit hashes & metadata into
 *      a 32-byte digest (NOT cryptographically strong; diagnostic only).
 *  fossil_ai_jellyfish_knowledge_coverage:
 *    - Normalized estimate of “active knowledge density” across the fixed
 *      capacity with recency, type, trust, and immutability influences.
 *
 * BRANCH & HISTORY OPS
 * --------------------
 *  Branch create / checkout / find / head update:
 *    - Minimal branch namespace with fixed max count; head hash only
 *      (no per-branch ancestry indexing).
 *  Merge:
 *    - Synthesizes a merge commit with two parents (target first).
 *    - Heuristic conflict flag if identical inputs map to divergent outputs.
 *  Rebase:
 *    - Creates a new commit with onto-head as single parent (source head
 *      content replay); updates source branch head.
 *  Cherry-pick:
 *    - Replicates source commit IO onto active branch head with optional
 *      single parent (current head); message annotated.
 *
 * BLOCK MUTATORS & CLASSIFICATION
 * -------------------------------
 *  Tagging / reason / similarity / link_forward / link_cross / redaction /
 *  immutability:
 *    - Controlled, bounded-size arrays (e.g., tags) avoid dynamic
 *      allocations per operation.
 *    - Similarity drives hallucinated / contradicted flags & confidence
 *      adjustment heuristics.
 *    - Redaction scrubs potential sensitive substrings (emails, UUIDs,
 *      long digit runs, large hex blobs) then re-hashes content to avoid
 *      stale addresses.
 *    - Immutability escalation upgrades ephemeral commit types (draft,
 *      experiment, stash) into archival semantics and enforces confidence
 *      floor if validated/signed/release/archived.
 *
 * FSON MINI-FRAMEWORK
 * -------------------
 *  - Compact typed tree supporting NULL / scalars / ENUM / ARRAY / OBJECT /
 *    CSTR with deep-copy, reset, and selective push/put semantics.
 *  - Capacity limits (FOSSIL_JELLYFISH_FSON_MAX_OBJECT / _MAX_ARRAY) maintain
 *    predictable footprints; keys are trimmed & length-checked.
 *  - copy() performs deep duplication with defensive allocation checks.
 *  - Attachments array in each block allows auxiliary structured payloads
 *    (e.g., evaluations, patches, annotations) without altering core hash.
 *
 * CRYPTO-LIKE (NON-CRYPTO) SIGNING
 * --------------------------------
 *  block_sign / block_verify_signature:
 *    - Derives two Jellyfish hashes over canonicalized textual buffers
 *      (priv/pub key fragments + IO + ancestry + type) spliced into a
 *      64-byte signature region. Provides tamper-evident hint only—
 *      no public-key cryptography; purely deterministic hashing.
 *
 * PERFORMANCE & COMPLEXITY NOTES
 * ------------------------------
 *  - Most operations are O(N) with N = FOSSIL_JELLYFISH_MAX_MEM (bounded).
 *  - No dynamic resizing; memory profile stable.
 *  - Hot paths (reasoning, find, audit) rely on simple linear scans with
 *    early exits where possible (exact matches / threshold breakouts).
 *
 * SAFETY & LIMITATIONS
 * --------------------
 *  - Not cryptographically secure (hashing, signing, salting, fingerprint).
 *  - No concurrency controls; caller must serialize access.
 *  - Persistence omits deep FSON trees (future extension hook).
 *  - Branch model is shallow; no reachability or merge-base computation.
 *
 * EXTENSION POINTS
 * ----------------
 *  - Replace hashing with stronger digest if collision risk unacceptable.
 *  - Add LRU or index structures (token inverted index) for sub-linear
 *    reasoning queries.
 *  - Enhance persistence to serialize full FSON metadata / attachments.
 *  - Introduce configurable retention & eviction policies (age + score).
 *
 * QUICK FUNCTION ROLE MAP
 * -----------------------
 *  Initialization: init
 *  Add / mutate: learn, update, add_commit, commit_set_parents
 *  Query: reason, reason_verbose, best_match, find, find_by_hash
 *  Integrity: audit, verify_chain, verify_block
 *  Hygiene: cleanup, prune, trim, deduplicate, compress_chain, chain_compact
 *  Metrics: chain_trust_score, chain_fingerprint, knowledge_coverage,
 *           chain_stats, block_age
 *  History ops: merge, rebase, cherry_pick, branch_* group
 *  Classification & tagging: block_add_tag, block_set_reason, block_set_similarity
 *  Security-lite: block_sign, block_verify_signature
 *  Persistence: save, load, clone_chain
 *
 * -----------------------------------------------------------------------------
 */

void fossil_ai_jellyfish_init(fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return;

    /* Zero top-level (safe because all pointers inside FSON values are individually reset next) */
    memset(chain, 0, sizeof(*chain));

    /* Repo timestamps */
    uint64_t now = get_time_microseconds();
    chain->created_at = now;
    chain->updated_at = now;

    /* Default branch name */
    strcpy(chain->default_branch, "main");

    /* Initialize repo_meta as OBJECT root */
    fossil_ai_jellyfish_fson_init(&chain->repo_meta);
    fossil_ai_jellyfish_fson_make_object(&chain->repo_meta);

    /* Create initial branch[0] */
    chain->branch_count = 1;
    strcpy(chain->branches[0].name, "main");
    fossil_ai_jellyfish_fson_init(&chain->branches[0].branch_meta);
    fossil_ai_jellyfish_fson_make_object(&chain->branches[0].branch_meta);

    /* Derive a pseudo device/repo id (mix salt + time) */
    uint64_t salt = get_device_salt();
    for (size_t i = 0; i < FOSSIL_DEVICE_ID_SIZE; ++i) {
        uint64_t v = (salt >> ((i % 8) * 8)) ^ (now >> (((i + 3) % 8) * 8));
        chain->repo_id[i] = (uint8_t)(v & 0xFF);
    }

    /* Initialize all commit slots */
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        memset(b, 0, sizeof(*b));

        b->identity.commit_index = (uint32_t)i;
        b->block_type = JELLY_COMMIT_UNKNOWN;

        fossil_ai_jellyfish_fson_init(&b->classify.semantic_meta);
        fossil_ai_jellyfish_fson_init(&b->io.io_meta);
        fossil_ai_jellyfish_fson_init(&b->fson.root);
        fossil_ai_jellyfish_fson_init(&b->audit_meta);

        /* Attributes neutral */
        b->attributes.valid = 0;
        b->attributes.confidence = 0.0f;

        /* Set cross/forward ref counts */
        b->classify.cross_ref_count = 0;
        b->classify.forward_ref_count = 0;

        /* Time stamps */
        b->time.timestamp = 0;
        b->time.updated_at = 0;
        b->time.expires_at = 0;
    }

    chain->count = 0;
}

/**
 * Learn a new input-output pair (creates an INFER commit).
 */
void fossil_ai_jellyfish_learn(fossil_ai_jellyfish_chain_t *chain, const char *input, const char *output) {
    if (!chain || !input || !output) return;

    size_t index = SIZE_MAX;

    /* Prefer append if room */
    if (chain->count < FOSSIL_JELLYFISH_MAX_MEM) {
        index = chain->count;
    } else {
        /* Reuse first invalid slot (lazy GC) */
        for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
            if (!chain->commits[i].attributes.valid) {
                index = i;
                break;
            }
        }
    }
    if (index == SIZE_MAX) return; /* No capacity */

    fossil_ai_jellyfish_block_t *b = &chain->commits[index];
    memset(b, 0, sizeof(*b));

    /* Core IO */
    strncpy(b->io.input, input, FOSSIL_JELLYFISH_INPUT_SIZE - 1);
    b->io.input[FOSSIL_JELLYFISH_INPUT_SIZE - 1] = '\0';
    strncpy(b->io.output, output, FOSSIL_JELLYFISH_OUTPUT_SIZE - 1);
    b->io.output[FOSSIL_JELLYFISH_OUTPUT_SIZE - 1] = '\0';

    b->io.input_len  = strlen(b->io.input);
    b->io.output_len = strlen(b->io.output);

    /* Tokenize */
    b->io.input_token_count  = fossil_ai_jellyfish_tokenize(b->io.input,
                                b->io.input_tokens, FOSSIL_JELLYFISH_MAX_TOKENS);
    b->io.output_token_count = fossil_ai_jellyfish_tokenize(b->io.output,
                                b->io.output_tokens, FOSSIL_JELLYFISH_MAX_TOKENS);

    /* Hash (content address) */
    fossil_ai_jellyfish_hash(b->io.input, b->io.output, b->identity.commit_hash);
    /* For now mirror commit hash as tree hash */
    memcpy(b->identity.tree_hash, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);

    /* Index / ancestry */
    b->identity.commit_index = (uint32_t)index;
    b->identity.parent_count = 0;
    b->identity.branch_id = 0;
    b->identity.is_merge_commit = 0;
    b->identity.detached = 0;
    b->identity.signature_len = 0;
    b->block_type = JELLY_COMMIT_INFER;

    /* Author/committer: reuse repo id */
    memcpy(b->identity.author_id,   chain->repo_id, FOSSIL_DEVICE_ID_SIZE);
    memcpy(b->identity.committer_id, chain->repo_id, FOSSIL_DEVICE_ID_SIZE);

    b->identity.commit_message[0] = '\0';

    /* Classification / meta init */
    fossil_ai_jellyfish_fson_init(&b->classify.semantic_meta);
    fossil_ai_jellyfish_fson_make_object(&b->classify.semantic_meta);
    fossil_ai_jellyfish_fson_init(&b->io.io_meta);
    fossil_ai_jellyfish_fson_make_object(&b->io.io_meta);
    fossil_ai_jellyfish_fson_init(&b->fson.root);
    fossil_ai_jellyfish_fson_make_object(&b->fson.root);
    fossil_ai_jellyfish_fson_init(&b->audit_meta);
    fossil_ai_jellyfish_fson_make_object(&b->audit_meta);

    /* Attributes */
    b->attributes.valid = 1;
    b->attributes.immutable = 0;
    b->attributes.confidence = 0.75f; /* heuristic base */
    b->attributes.usage_count = 0;

    /* Timing */
    uint64_t now = get_time_microseconds();
    b->time.timestamp = now;
    b->time.updated_at = now;
    b->time.delta_ms = 0;
    b->time.duration_ms = 0;
    b->time.expires_at = 0;
    b->time.validated_at = 0;

    /* Chain bookkeeping */
    if (index == chain->count && chain->count < FOSSIL_JELLYFISH_MAX_MEM)
        chain->count++;
    chain->updated_at = now;

    /* Update active (default) branch head */
    if (chain->branch_count > 0) {
        memcpy(chain->branches[0].head_hash, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);
    }
}

void fossil_ai_jellyfish_remove(fossil_ai_jellyfish_chain_t *chain, size_t index) {
    if (!chain || index >= FOSSIL_JELLYFISH_MAX_MEM)
        return;

    fossil_ai_jellyfish_block_t *block = &chain->commits[index];
    block->attributes.valid = 0;
    block->attributes.pruned = 1;
    block->attributes.confidence = 0.0f;
    block->time.expires_at = get_time_microseconds();
}

fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_find(fossil_ai_jellyfish_chain_t *chain, const uint8_t *hash) {
    if (!chain || !hash) return NULL;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (b->attributes.valid &&
            memcmp(b->identity.commit_hash, hash, FOSSIL_JELLYFISH_HASH_SIZE) == 0) {
            return b;
        }
    }
    return NULL;
}

void fossil_ai_jellyfish_update(fossil_ai_jellyfish_chain_t *chain, size_t index,
                                const char *input, const char *output) {
    if (!chain || index >= FOSSIL_JELLYFISH_MAX_MEM) return;
    fossil_ai_jellyfish_block_t *b = &chain->commits[index];
    if (!b->attributes.valid || b->attributes.immutable) return;

    uint8_t old_hash[FOSSIL_JELLYFISH_HASH_SIZE];
    memcpy(old_hash, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);

    /* Update IO (allow partial update if one is NULL) */
    if (input) {
        strncpy(b->io.input, input, FOSSIL_JELLYFISH_INPUT_SIZE - 1);
        b->io.input[FOSSIL_JELLYFISH_INPUT_SIZE - 1] = '\0';
    }
    if (output) {
        strncpy(b->io.output, output, FOSSIL_JELLYFISH_OUTPUT_SIZE - 1);
        b->io.output[FOSSIL_JELLYFISH_OUTPUT_SIZE - 1] = '\0';
    }

    b->io.input_len  = strlen(b->io.input);
    b->io.output_len = strlen(b->io.output);

    b->io.input_token_count  = fossil_ai_jellyfish_tokenize(
        b->io.input, b->io.input_tokens, FOSSIL_JELLYFISH_MAX_TOKENS);
    b->io.output_token_count = fossil_ai_jellyfish_tokenize(
        b->io.output, b->io.output_tokens, FOSSIL_JELLYFISH_MAX_TOKENS);

    fossil_ai_jellyfish_hash(b->io.input, b->io.output, b->identity.commit_hash);
    memcpy(b->identity.tree_hash, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);

    /* If original was an INFER, upgrading to PATCH makes sense */
    if (b->block_type == JELLY_COMMIT_INFER)
        b->block_type = JELLY_COMMIT_PATCH;

    uint64_t now = get_time_microseconds();
    uint64_t prev_upd = b->time.updated_at ? b->time.updated_at : b->time.timestamp;
    b->time.delta_ms = (uint32_t)((now - prev_upd) / 1000ULL);
    b->time.updated_at = now;

    /* Light confidence adjustment (decay + small bump) */
    b->attributes.confidence = (b->attributes.confidence * 0.90f) + 0.05f;
    if (b->attributes.confidence > 1.0f) b->attributes.confidence = 1.0f;
    if (b->attributes.confidence < 0.0f) b->attributes.confidence = 0.0f;

    /* Update branch heads that pointed to old hash */
    for (size_t i = 0; i < chain->branch_count; ++i) {
        if (memcmp(chain->branches[i].head_hash, old_hash, FOSSIL_JELLYFISH_HASH_SIZE) == 0) {
            memcpy(chain->branches[i].head_hash, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);
        }
    }

    chain->updated_at = now;
}

/* ---------------------------- Persistence ---------------------------------- */

int fossil_ai_jellyfish_save(const fossil_ai_jellyfish_chain_t *chain, const char *filepath) {
    if (!chain || !filepath) return -1;

    FILE *fp = fopen(filepath, "wb");
    if (!fp) return -1;

    /* ---------- Header ---------- */
    struct header {
        char     magic[8];
        uint32_t version;
        uint32_t commit_capacity;
        uint32_t commit_count;      /* chain->count (occupied slots, may include invalid) */
        uint32_t valid_count;       /* number of valid blocks serialized */
        uint32_t branch_count;
        uint64_t created_at;
        uint64_t updated_at;
        uint8_t  repo_id[FOSSIL_DEVICE_ID_SIZE];
        char     default_branch[64];
    } hdr;

    memset(&hdr, 0, sizeof(hdr));
    memcpy(hdr.magic, "JFCHAIN", 7);
    hdr.version          = 1;
    hdr.commit_capacity  = (uint32_t)FOSSIL_JELLYFISH_MAX_MEM;
    hdr.commit_count     = (uint32_t)chain->count;
    hdr.branch_count     = (uint32_t)chain->branch_count;
    hdr.created_at       = chain->created_at;
    hdr.updated_at       = chain->updated_at;
    memcpy(hdr.repo_id, chain->repo_id, FOSSIL_DEVICE_ID_SIZE);
    strncpy(hdr.default_branch, chain->default_branch, sizeof(hdr.default_branch) - 1);

    /* Count valid blocks */
    uint32_t valid_count = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i)
        if (chain->commits[i].attributes.valid) valid_count++;
    hdr.valid_count = valid_count;

    if (fwrite(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr)) {
        fclose(fp);
        return -1;
    }

    /* ---------- Branch records ---------- */
    struct branch_rec {
        char name[64];
        uint8_t head_hash[FOSSIL_JELLYFISH_HASH_SIZE];
    } br;

    for (size_t b = 0; b < chain->branch_count; ++b) {
        memset(&br, 0, sizeof(br));
        strncpy(br.name, chain->branches[b].name, sizeof(br.name) - 1);
        memcpy(br.head_hash, chain->branches[b].head_hash, FOSSIL_JELLYFISH_HASH_SIZE);
        if (fwrite(&br, 1, sizeof(br), fp) != sizeof(br)) {
            fclose(fp);
            return -1;
        }
    }

    /* ---------- Commit records ---------- */
    struct commit_rec {
        uint32_t index;
        uint8_t  block_type;
        uint8_t  parent_count;
        uint8_t  is_merge_commit;
        uint8_t  detached;

        uint8_t  commit_hash[FOSSIL_JELLYFISH_HASH_SIZE];
        uint8_t  tree_hash[FOSSIL_JELLYFISH_HASH_SIZE];
        uint8_t  parent_hashes[4][FOSSIL_JELLYFISH_HASH_SIZE];

        uint8_t  author_id[FOSSIL_DEVICE_ID_SIZE];
        uint8_t  committer_id[FOSSIL_DEVICE_ID_SIZE];

        uint32_t signature_len;
        uint8_t  signature[FOSSIL_SIGNATURE_SIZE];

        char     commit_message[256];

        /* IO */
        char     input[FOSSIL_JELLYFISH_INPUT_SIZE];
        char     output[FOSSIL_JELLYFISH_OUTPUT_SIZE];
        uint32_t input_len;
        uint32_t output_len;

        uint32_t input_token_count;
        uint32_t output_token_count;
        char     input_tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
        char     output_tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];

        /* Timing */
        uint64_t timestamp;
        uint32_t delta_ms;
        uint32_t duration_ms;
        uint64_t updated_at;
        uint64_t expires_at;
        uint64_t validated_at;

        /* Attributes */
        float    confidence;
        uint32_t usage_count;
        uint8_t  attr_flags; /* bitfield of attribute booleans */
        uint8_t  reserved[7]; /* padding for future */

    } rec;

    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;

        memset(&rec, 0, sizeof(rec));
        rec.index            = b->identity.commit_index;
        rec.block_type       = (uint8_t)b->block_type;
        rec.parent_count     = (uint8_t)b->identity.parent_count;
        rec.is_merge_commit  = (uint8_t)b->identity.is_merge_commit;
        rec.detached         = (uint8_t)b->identity.detached;

        memcpy(rec.commit_hash, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);
        memcpy(rec.tree_hash,   b->identity.tree_hash,   FOSSIL_JELLYFISH_HASH_SIZE);
        for (size_t p = 0; p < b->identity.parent_count && p < 4; ++p)
            memcpy(rec.parent_hashes[p], b->identity.parent_hashes[p], FOSSIL_JELLYFISH_HASH_SIZE);

        memcpy(rec.author_id,    b->identity.author_id,    FOSSIL_DEVICE_ID_SIZE);
        memcpy(rec.committer_id, b->identity.committer_id, FOSSIL_DEVICE_ID_SIZE);

        rec.signature_len = b->identity.signature_len > FOSSIL_SIGNATURE_SIZE
                            ? FOSSIL_SIGNATURE_SIZE : b->identity.signature_len;
        if (rec.signature_len)
            memcpy(rec.signature, b->identity.signature, rec.signature_len);

        strncpy(rec.commit_message, b->identity.commit_message, sizeof(rec.commit_message) - 1);

        strncpy(rec.input,  b->io.input,  sizeof(rec.input)  - 1);
        strncpy(rec.output, b->io.output, sizeof(rec.output) - 1);
        rec.input_len          = (uint32_t)b->io.input_len;
        rec.output_len         = (uint32_t)b->io.output_len;
        rec.input_token_count  = (uint32_t)b->io.input_token_count;
        rec.output_token_count = (uint32_t)b->io.output_token_count;

        for (size_t t = 0; t < b->io.input_token_count && t < FOSSIL_JELLYFISH_MAX_TOKENS; ++t)
            strncpy(rec.input_tokens[t], b->io.input_tokens[t], FOSSIL_JELLYFISH_TOKEN_SIZE - 1);
        for (size_t t = 0; t < b->io.output_token_count && t < FOSSIL_JELLYFISH_MAX_TOKENS; ++t)
            strncpy(rec.output_tokens[t], b->io.output_tokens[t], FOSSIL_JELLYFISH_TOKEN_SIZE - 1);

        rec.timestamp    = b->time.timestamp;
        rec.delta_ms     = b->time.delta_ms;
        rec.duration_ms  = b->time.duration_ms;
        rec.updated_at   = b->time.updated_at;
        rec.expires_at   = b->time.expires_at;
        rec.validated_at = b->time.validated_at;

        rec.confidence   = b->attributes.confidence;
        rec.usage_count  = b->attributes.usage_count;

        /* Pack attribute booleans into bitfield */
        rec.attr_flags =
            (b->attributes.immutable   ? 1u << 0 : 0) |
            (b->attributes.valid       ? 1u << 1 : 0) |
            (b->attributes.pruned      ? 1u << 2 : 0) |
            (b->attributes.redacted    ? 1u << 3 : 0) |
            (b->attributes.deduplicated? 1u << 4 : 0) |
            (b->attributes.compressed  ? 1u << 5 : 0) |
            (b->attributes.expired     ? 1u << 6 : 0) |
            (b->attributes.trusted     ? 1u << 7 : 0);

        if (fwrite(&rec, 1, sizeof(rec), fp) != sizeof(rec)) {
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

int fossil_ai_jellyfish_load(fossil_ai_jellyfish_chain_t *chain, const char *filepath) {
    if (!chain || !filepath) return -1;
    FILE *fp = fopen(filepath, "rb");
    if (!fp) return -1;

    struct header {
        char     magic[8];
        uint32_t version;
        uint32_t commit_capacity;
        uint32_t commit_count;
        uint32_t valid_count;
        uint32_t branch_count;
        uint64_t created_at;
        uint64_t updated_at;
        uint8_t  repo_id[FOSSIL_DEVICE_ID_SIZE];
        char     default_branch[64];
    } hdr;

    if (fread(&hdr, 1, sizeof(hdr), fp) != sizeof(hdr)) { fclose(fp); return -1; }
    if (memcmp(hdr.magic, "JFCHAIN", 7) != 0) { fclose(fp); return -1; }
    if (hdr.version != 1) { fclose(fp); return -1; }
    if (hdr.commit_capacity != FOSSIL_JELLYFISH_MAX_MEM) { fclose(fp); return -1; }
    if (hdr.branch_count > FOSSIL_JELLYFISH_MAX_BRANCHES) { fclose(fp); return -1; }

    /* Wipe and rebuild */
    memset(chain, 0, sizeof(*chain));
    chain->created_at   = hdr.created_at;
    chain->updated_at   = hdr.updated_at;
    chain->branch_count = hdr.branch_count;
    memcpy(chain->repo_id, hdr.repo_id, FOSSIL_DEVICE_ID_SIZE);
    strncpy(chain->default_branch, hdr.default_branch, sizeof(chain->default_branch)-1);

    /* Initialize repo_meta root */
    fossil_ai_jellyfish_fson_init(&chain->repo_meta);
    fossil_ai_jellyfish_fson_make_object(&chain->repo_meta);

    struct branch_rec {
        char name[64];
        uint8_t head_hash[FOSSIL_JELLYFISH_HASH_SIZE];
    } br;

    for (size_t b = 0; b < chain->branch_count; ++b) {
        if (fread(&br, 1, sizeof(br), fp) != sizeof(br)) { fclose(fp); return -1; }
        strncpy(chain->branches[b].name, br.name, sizeof(chain->branches[b].name)-1);
        memcpy(chain->branches[b].head_hash, br.head_hash, FOSSIL_JELLYFISH_HASH_SIZE);
        fossil_ai_jellyfish_fson_init(&chain->branches[b].branch_meta);
        fossil_ai_jellyfish_fson_make_object(&chain->branches[b].branch_meta);
    }

    struct commit_rec {
        uint32_t index;
        uint8_t  block_type;
        uint8_t  parent_count;
        uint8_t  is_merge_commit;
        uint8_t  detached;

        uint8_t  commit_hash[FOSSIL_JELLYFISH_HASH_SIZE];
        uint8_t  tree_hash[FOSSIL_JELLYFISH_HASH_SIZE];
        uint8_t  parent_hashes[4][FOSSIL_JELLYFISH_HASH_SIZE];

        uint8_t  author_id[FOSSIL_DEVICE_ID_SIZE];
        uint8_t  committer_id[FOSSIL_DEVICE_ID_SIZE];

        uint32_t signature_len;
        uint8_t  signature[FOSSIL_SIGNATURE_SIZE];

        char     commit_message[256];

        char     input[FOSSIL_JELLYFISH_INPUT_SIZE];
        char     output[FOSSIL_JELLYFISH_OUTPUT_SIZE];
        uint32_t input_len;
        uint32_t output_len;

        uint32_t input_token_count;
        uint32_t output_token_count;
        char     input_tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
        char     output_tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];

        uint64_t timestamp;
        uint32_t delta_ms;
        uint32_t duration_ms;
        uint64_t updated_at;
        uint64_t expires_at;
        uint64_t validated_at;

        float    confidence;
        uint32_t usage_count;
        uint8_t  attr_flags;
        uint8_t  reserved[7];
    } rec;

    uint32_t loaded_valid = 0;
    uint32_t max_index_plus1 = 0;

    while (loaded_valid < hdr.valid_count) {
        if (fread(&rec, 1, sizeof(rec), fp) != sizeof(rec)) { fclose(fp); return -1; }
        if (rec.index >= FOSSIL_JELLYFISH_MAX_MEM) { fclose(fp); return -1; }

        fossil_ai_jellyfish_block_t *b = &chain->commits[rec.index];
        memset(b, 0, sizeof(*b));

        /* Identity */
        b->identity.commit_index    = rec.index;
        b->block_type               = (fossil_ai_jellyfish_commit_type_t)rec.block_type;
        b->identity.parent_count    = rec.parent_count > 4 ? 4 : rec.parent_count;
        b->identity.is_merge_commit = rec.is_merge_commit;
        b->identity.detached        = rec.detached;

        memcpy(b->identity.commit_hash, rec.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);
        memcpy(b->identity.tree_hash,   rec.tree_hash,   FOSSIL_JELLYFISH_HASH_SIZE);
        for (size_t p = 0; p < b->identity.parent_count; ++p)
            memcpy(b->identity.parent_hashes[p], rec.parent_hashes[p], FOSSIL_JELLYFISH_HASH_SIZE);

        memcpy(b->identity.author_id,    rec.author_id,    FOSSIL_DEVICE_ID_SIZE);
        memcpy(b->identity.committer_id, rec.committer_id, FOSSIL_DEVICE_ID_SIZE);

        b->identity.signature_len = rec.signature_len > FOSSIL_SIGNATURE_SIZE ?
                                    FOSSIL_SIGNATURE_SIZE : rec.signature_len;
        if (b->identity.signature_len)
            memcpy(b->identity.signature, rec.signature, b->identity.signature_len);

        strncpy(b->identity.commit_message, rec.commit_message,
                sizeof(b->identity.commit_message)-1);

        /* IO */
        strncpy(b->io.input,  rec.input,  sizeof(b->io.input)-1);
        strncpy(b->io.output, rec.output, sizeof(b->io.output)-1);
        b->io.input_len          = rec.input_len;
        b->io.output_len         = rec.output_len;
        b->io.input_token_count  = rec.input_token_count <= FOSSIL_JELLYFISH_MAX_TOKENS ?
                                   rec.input_token_count : FOSSIL_JELLYFISH_MAX_TOKENS;
        b->io.output_token_count = rec.output_token_count <= FOSSIL_JELLYFISH_MAX_TOKENS ?
                                   rec.output_token_count : FOSSIL_JELLYFISH_MAX_TOKENS;
        for (size_t t=0; t<b->io.input_token_count; ++t)
            strncpy(b->io.input_tokens[t], rec.input_tokens[t], FOSSIL_JELLYFISH_TOKEN_SIZE-1);
        for (size_t t=0; t<b->io.output_token_count; ++t)
            strncpy(b->io.output_tokens[t], rec.output_tokens[t], FOSSIL_JELLYFISH_TOKEN_SIZE-1);

        /* Timing */
        b->time.timestamp    = rec.timestamp;
        b->time.delta_ms     = rec.delta_ms;
        b->time.duration_ms  = rec.duration_ms;
        b->time.updated_at   = rec.updated_at;
        b->time.expires_at   = rec.expires_at;
        b->time.validated_at = rec.validated_at;

        /* Attributes */
        b->attributes.confidence  = rec.confidence;
        b->attributes.usage_count = rec.usage_count;
        b->attributes.immutable    = (rec.attr_flags & (1u<<0)) ? 1:0;
        b->attributes.valid        = (rec.attr_flags & (1u<<1)) ? 1:0;
        b->attributes.pruned       = (rec.attr_flags & (1u<<2)) ? 1:0;
        b->attributes.redacted     = (rec.attr_flags & (1u<<3)) ? 1:0;
        b->attributes.deduplicated = (rec.attr_flags & (1u<<4)) ? 1:0;
        b->attributes.compressed   = (rec.attr_flags & (1u<<5)) ? 1:0;
        b->attributes.expired      = (rec.attr_flags & (1u<<6)) ? 1:0;
        b->attributes.trusted      = (rec.attr_flags & (1u<<7)) ? 1:0;

        /* Initialize FSON sub-objects (not serialized) */
        fossil_ai_jellyfish_fson_init(&b->classify.semantic_meta);
        fossil_ai_jellyfish_fson_make_object(&b->classify.semantic_meta);
        fossil_ai_jellyfish_fson_init(&b->io.io_meta);
        fossil_ai_jellyfish_fson_make_object(&b->io.io_meta);
        fossil_ai_jellyfish_fson_init(&b->fson.root);
        fossil_ai_jellyfish_fson_make_object(&b->fson.root);
        fossil_ai_jellyfish_fson_init(&b->audit_meta);
        fossil_ai_jellyfish_fson_make_object(&b->audit_meta);

        if (b->identity.commit_index + 1 > max_index_plus1)
            max_index_plus1 = b->identity.commit_index + 1;

        loaded_valid++;
    }

    fclose(fp);

    /* chain->count should reflect highest occupied index (like original) */
    chain->count = hdr.commit_count;
    if (chain->count < max_index_plus1)
        chain->count = max_index_plus1;
    if (chain->count > FOSSIL_JELLYFISH_MAX_MEM)
        chain->count = FOSSIL_JELLYFISH_MAX_MEM;

    return 0;
}

/* ----------------------------- Maintenance --------------------------------- */

void fossil_ai_jellyfish_cleanup(fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return;

    uint64_t now = get_time_microseconds();
    size_t highest_valid = 0;
    int any_valid = 0;

    /* Pass 1: per-block hygiene */
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        fossil_ai_jellyfish_block_t *b = &chain->commits[i];

        /* Skip never-used slots quickly (confidence already zeroed) */
        if (!b->attributes.valid && b->time.timestamp == 0)
            continue;

        /* Expiration handling */
        if (b->attributes.valid &&
            b->time.expires_at != 0 &&
            now >= b->time.expires_at) {
            b->attributes.expired = 1;
            b->attributes.valid = 0;
            b->attributes.confidence = 0.0f;
        }

        /* Invariant: confidence bounds */
        if (b->attributes.confidence < 0.0f) b->attributes.confidence = 0.0f;
        if (b->attributes.confidence > 1.0f) b->attributes.confidence = 1.0f;

        /* Invalidate confidence for non-valid blocks */
        if (!b->attributes.valid)
            b->attributes.confidence = 0.0f;

        /* Clamp counts */
        if (b->identity.parent_count > 4)
            b->identity.parent_count = 4;
        if (b->classify.cross_ref_count > FOSSIL_JELLYFISH_MAX_LINKS)
            b->classify.cross_ref_count = FOSSIL_JELLYFISH_MAX_LINKS;
        if (b->classify.forward_ref_count > FOSSIL_JELLYFISH_MAX_LINKS)
            b->classify.forward_ref_count = FOSSIL_JELLYFISH_MAX_LINKS;
        if (b->io.input_token_count > FOSSIL_JELLYFISH_MAX_TOKENS)
            b->io.input_token_count = FOSSIL_JELLYFISH_MAX_TOKENS;
        if (b->io.output_token_count > FOSSIL_JELLYFISH_MAX_TOKENS)
            b->io.output_token_count = FOSSIL_JELLYFISH_MAX_TOKENS;

        /* Length guards (defensive) */
        if (b->io.input_len >= FOSSIL_JELLYFISH_INPUT_SIZE)
            b->io.input[FOSSIL_JELLYFISH_INPUT_SIZE - 1] = '\0';
        if (b->io.output_len >= FOSSIL_JELLYFISH_OUTPUT_SIZE)
            b->io.output[FOSSIL_JELLYFISH_OUTPUT_SIZE - 1] = '\0';
        b->io.input_len = strnlen(b->io.input, FOSSIL_JELLYFISH_INPUT_SIZE);
        b->io.output_len = strnlen(b->io.output, FOSSIL_JELLYFISH_OUTPUT_SIZE);

        /* Merge flag consistency */
        if (b->identity.parent_count >= 2)
            b->identity.is_merge_commit = 1;
        else if (b->identity.is_merge_commit && b->identity.parent_count < 2)
            b->identity.is_merge_commit = 0;

        /* Detached heuristic: if block_type denotes detached or parent_count==0 (non-genesis) */
        if (b->block_type == JELLY_COMMIT_DETACHED)
            b->identity.detached = 1;

        /* Track highest valid index */
        if (b->attributes.valid) {
            any_valid = 1;
            if (i + 1 > highest_valid)
                highest_valid = i + 1;
        }
    }

    /* Logical chain->count shrink (do not reorder) */
    if (any_valid)
        chain->count = highest_valid;
    else
        chain->count = 0;

    /* Pass 2: sanitize branch heads (ensure they point to an existing valid commit) */
    for (size_t br = 0; br < chain->branch_count; ++br) {
        int found = 0;
        for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM && !found; ++i) {
            fossil_ai_jellyfish_block_t *b = &chain->commits[i];
            if (b->attributes.valid &&
                memcmp(b->identity.commit_hash,
                       chain->branches[br].head_hash,
                       FOSSIL_JELLYFISH_HASH_SIZE) == 0) {
                found = 1;
            }
        }
        if (!found) {
            memset(chain->branches[br].head_hash, 0, FOSSIL_JELLYFISH_HASH_SIZE);
        }
    }

    chain->updated_at = now;
}

int fossil_ai_jellyfish_audit(const fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return -1;
    int anomalies = 0;

    /* Precompute list of valid commit hashes for quick parent existence tests */
    uint8_t valid_hashes[FOSSIL_JELLYFISH_MAX_MEM][FOSSIL_JELLYFISH_HASH_SIZE];
    size_t  valid_indices[FOSSIL_JELLYFISH_MAX_MEM];
    size_t  valid_count = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (b->attributes.valid) {
            memcpy(valid_hashes[valid_count], b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);
            valid_indices[valid_count] = i;
            valid_count++;
        }
    }

    for (size_t idx = 0; idx < FOSSIL_JELLYFISH_MAX_MEM; ++idx) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[idx];
        if (!b->attributes.valid) continue;

        /* 1. Index consistency */
        if (b->identity.commit_index != idx)
            anomalies++;

        /* 2. Hash recomputation (content based) */
        uint8_t recomputed[FOSSIL_JELLYFISH_HASH_SIZE];
        fossil_ai_jellyfish_hash(b->io.input, b->io.output, recomputed);
        if (memcmp(recomputed, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE) != 0)
            anomalies++;

        /* Zero hash disallowed */
        int all_zero = 1;
        for (size_t k = 0; k < FOSSIL_JELLYFISH_HASH_SIZE; ++k)
            if (b->identity.commit_hash[k] != 0) { all_zero = 0; break; }
        if (all_zero)
            anomalies++;

        /* 3. Parent constraints */
        if (b->identity.parent_count > 4)
            anomalies++;
        for (size_t p = 0; p < b->identity.parent_count && p < 4; ++p) {
            int found = 0;
            for (size_t vh = 0; vh < valid_count; ++vh) {
                if (memcmp(valid_hashes[vh], b->identity.parent_hashes[p], FOSSIL_JELLYFISH_HASH_SIZE) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found)
                anomalies++;
        }

        /* 4. Merge flag consistency */
        if ((b->identity.parent_count >= 2 && !b->identity.is_merge_commit) ||
            (b->identity.parent_count < 2 && b->identity.is_merge_commit))
            anomalies++;

        /* 5. Length & token bounds */
        size_t real_in_len = strnlen(b->io.input, FOSSIL_JELLYFISH_INPUT_SIZE);
        size_t real_out_len = strnlen(b->io.output, FOSSIL_JELLYFISH_OUTPUT_SIZE);
        if (real_in_len != b->io.input_len) anomalies++;
        if (real_out_len != b->io.output_len) anomalies++;
        if (b->io.input_token_count > FOSSIL_JELLYFISH_MAX_TOKENS) anomalies++;
        if (b->io.output_token_count > FOSSIL_JELLYFISH_MAX_TOKENS) anomalies++;

        /* 6. Confidence range */
        if (b->attributes.confidence < 0.0f || b->attributes.confidence > 1.0f)
            anomalies++;

        /* 7. Trusted flag heuristic: signed commit type without signature */
        if (b->block_type == JELLY_COMMIT_SIGNED && b->identity.signature_len == 0)
            anomalies++;

        /* 8. Merge type sanity */
        if (b->block_type == JELLY_COMMIT_MERGE && b->identity.parent_count < 2)
            anomalies++;
    }

    /* 9. Branch head validity */
    for (size_t br = 0; br < chain->branch_count; ++br) {
        const uint8_t *head = chain->branches[br].head_hash;
        if (memcmp(head, "\0\0\0\0\0\0\0\0", 8) == 0) continue; /* tolerate zeroed */
        int found = 0;
        for (size_t vh = 0; vh < valid_count; ++vh) {
            if (memcmp(valid_hashes[vh], head, FOSSIL_JELLYFISH_HASH_SIZE) == 0) { found = 1; break; }
        }
        if (!found)
            anomalies++;
    }

    /* 10. Count consistency: chain->count should be >= highest valid index+1 (soft check) */
    size_t highest_valid = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i)
        if (chain->commits[i].attributes.valid && i + 1 > highest_valid)
            highest_valid = i + 1;
    if (highest_valid > chain->count)
        anomalies++;

    return anomalies;
}

int fossil_ai_jellyfish_prune(fossil_ai_jellyfish_chain_t *chain, float min_confidence) {
    if (!chain) return 0;
    if (min_confidence < 0.0f) min_confidence = 0.0f;
    if (min_confidence > 1.0f) min_confidence = 1.0f;

    uint64_t now = get_time_microseconds();
    int pruned = 0;

    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;

        int expired = (b->time.expires_at != 0 && now >= b->time.expires_at);
        int low_conf = (b->attributes.confidence < min_confidence);

        if (expired) b->attributes.expired = 1;

        if (expired || low_conf) {
            uint8_t old_hash[FOSSIL_JELLYFISH_HASH_SIZE];
            memcpy(old_hash, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);

            b->attributes.valid = 0;
            b->attributes.pruned = 1;
            b->attributes.confidence = 0.0f;
            b->block_type = JELLY_COMMIT_PRUNE;
            b->time.expires_at = now;

            /* Clear branch heads pointing here (will also be sanitized in cleanup) */
            for (size_t br = 0; br < chain->branch_count; ++br) {
                if (memcmp(chain->branches[br].head_hash, old_hash, FOSSIL_JELLYFISH_HASH_SIZE) == 0) {
                    memset(chain->branches[br].head_hash, 0, FOSSIL_JELLYFISH_HASH_SIZE);
                }
            }
            pruned++;
        }
    }

    if (pruned) {
        fossil_ai_jellyfish_cleanup(chain); /* updates count & branch heads, sets updated_at */
    }

    return pruned;
}

/* ------------------------------ Reasoning ---------------------------------- */

const char *fossil_ai_jellyfish_reason(fossil_ai_jellyfish_chain_t *chain, const char *input) {
    static const char *UNKNOWN = "Unknown";
    if (!chain || !input || !*input) return UNKNOWN;

    /* Tokenize query */
    char qtokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
    size_t qcount = fossil_ai_jellyfish_tokenize(input, qtokens, FOSSIL_JELLYFISH_MAX_TOKENS);

    fossil_ai_jellyfish_block_t *best = NULL;
    float best_score = -1.0f;

    uint64_t now = get_time_microseconds();

    size_t upper = chain->count;
    if (upper > FOSSIL_JELLYFISH_MAX_MEM) upper = FOSSIL_JELLYFISH_MAX_MEM;

    for (size_t i = 0; i < upper; ++i) {
        fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;

        /* Fast exact match */
        if (strcmp(b->io.input, input) == 0) {
            best = b;
            best_score = 1e9f; /* Sentinel high score */
            break;
        }

        /* Token overlap (Jaccard) */
        if (qcount == 0 || b->io.input_token_count == 0) continue;

        size_t match = 0;
        for (size_t q = 0; q < qcount; ++q) {
            for (size_t t = 0; t < b->io.input_token_count; ++t) {
                if (strncmp(qtokens[q], b->io.input_tokens[t], FOSSIL_JELLYFISH_TOKEN_SIZE) == 0) {
                    match++;
                    break;
                }
            }
        }
        if (match == 0) continue;

        size_t denom = qcount + b->io.input_token_count - match;
        float jaccard = denom ? (float)match / (float)denom : 0.0f;

        /* Freshness factor (recent blocks get slight boost) */
        float age_sec = (float)((now > b->time.timestamp) ? (now - b->time.timestamp) : 0ULL) / 1e6f;
        float freshness = (age_sec < 60.0f) ? 1.0f : (60.0f / (age_sec + 60.0f)); /* ~decays after 1 min */

        float weighted = jaccard * (0.5f + 0.5f * b->attributes.confidence) * (0.8f + 0.2f * freshness);

        /* Tie-break: confidence then recency */
        if (weighted > best_score ||
            (weighted == best_score && best &&
             (b->attributes.confidence > best->attributes.confidence ||
              (b->attributes.confidence == best->attributes.confidence &&
               b->time.timestamp > best->time.timestamp)))) {
            best = b;
            best_score = weighted;
        }
    }

    if (!best) return UNKNOWN;

    /* Lightweight reinforcement */
    best->attributes.usage_count++;
    if (best->attributes.confidence < 1.0f) {
        best->attributes.confidence += 0.01f;
        if (best->attributes.confidence > 1.0f)
            best->attributes.confidence = 1.0f;
    }

    return best->io.output[0] ? best->io.output : UNKNOWN;
}

bool fossil_ai_jellyfish_reason_verbose(const fossil_ai_jellyfish_chain_t *chain, const char *input,
                                     char *out_output, float *out_confidence,
                                     const fossil_ai_jellyfish_block_t **out_block) {
    static const char *UNKNOWN = "Unknown";
    if (!chain || !input || !*input) return false;

    if (out_output) out_output[0] = '\0';
    if (out_confidence) *out_confidence = 0.0f;
    if (out_block) *out_block = NULL;

    /* Tokenize query */
    char qtokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
    size_t qcount = fossil_ai_jellyfish_tokenize(input, qtokens, FOSSIL_JELLYFISH_MAX_TOKENS);

    const fossil_ai_jellyfish_block_t *best = NULL;
    float best_score = -1.0f;
    int exact = 0;

    uint64_t now = get_time_microseconds();
    size_t upper = chain->count;
    if (upper > FOSSIL_JELLYFISH_MAX_MEM) upper = FOSSIL_JELLYFISH_MAX_MEM;

    for (size_t i = 0; i < upper; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;

        /* Exact match fast path */
        if (strcmp(b->io.input, input) == 0) {
            best = b;
            best_score = 1.0f;
            exact = 1;
            break;
        }

        if (qcount == 0 || b->io.input_token_count == 0) continue;

        size_t match = 0;
        for (size_t q = 0; q < qcount; ++q) {
            for (size_t t = 0; t < b->io.input_token_count; ++t) {
                if (strncmp(qtokens[q], b->io.input_tokens[t], FOSSIL_JELLYFISH_TOKEN_SIZE) == 0) {
                    match++;
                    break;
                }
            }
        }
        if (match == 0) continue;

        size_t denom = qcount + b->io.input_token_count - match;
        float jaccard = denom ? (float)match / (float)denom : 0.0f;

        float age_sec = (float)((now > b->time.timestamp) ? (now - b->time.timestamp) : 0ULL) / 1e6f;
        float freshness = (age_sec < 60.0f) ? 1.0f : (60.0f / (age_sec + 60.0f));

        float weighted = jaccard * (0.5f + 0.5f * b->attributes.confidence) * (0.8f + 0.2f * freshness);

        if (weighted > best_score ||
            (weighted == best_score && best &&
             (b->attributes.confidence > best->attributes.confidence ||
              (b->attributes.confidence == best->attributes.confidence &&
               b->time.timestamp > best->time.timestamp)))) {
            best = b;
            best_score = weighted;
        }
    }

    if (!best) {
        if (out_output) {
            strncpy(out_output, UNKNOWN, FOSSIL_JELLYFISH_OUTPUT_SIZE - 1);
            out_output[FOSSIL_JELLYFISH_OUTPUT_SIZE - 1] = '\0';
        }
        return false;
    }

    if (exact) best_score = 1.0f;
    if (best_score < 0.0f) best_score = 0.0f;
    if (best_score > 1.0f) best_score = 1.0f;

    if (out_output) {
        const char *src = best->io.output[0] ? best->io.output : UNKNOWN;
        strncpy(out_output, src, FOSSIL_JELLYFISH_OUTPUT_SIZE - 1);
        out_output[FOSSIL_JELLYFISH_OUTPUT_SIZE - 1] = '\0';
    }
    if (out_confidence) *out_confidence = best_score;
    if (out_block) *out_block = best;

    return true;
}

const fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_best_match(
    const fossil_ai_jellyfish_chain_t *chain,
    const char *input)
{
    if (!chain || !input || !*input)
    return NULL;

    /* Tokenize query (bounded) */
    char qtokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
    size_t qcount = fossil_ai_jellyfish_tokenize(input, qtokens, FOSSIL_JELLYFISH_MAX_TOKENS);

    const fossil_ai_jellyfish_block_t *best = NULL;
    float best_score = -1.0f;
    uint64_t now = get_time_microseconds();

    size_t upper = chain->count;
    if (upper > FOSSIL_JELLYFISH_MAX_MEM)
    upper = FOSSIL_JELLYFISH_MAX_MEM;

    for (size_t i = 0; i < upper; ++i) {
    const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
    if (!b->attributes.valid)
        continue;

    /* Fast exact input match */
    if (strcmp(b->io.input, input) == 0) {
        return b; /* exact match wins outright */
    }

    if (qcount == 0 || b->io.input_token_count == 0)
        continue;

    /* Intersection count */
    size_t match = 0;
    for (size_t q = 0; q < qcount; ++q) {
        for (size_t t = 0; t < b->io.input_token_count; ++t) {
        if (strncmp(qtokens[q], b->io.input_tokens[t], FOSSIL_JELLYFISH_TOKEN_SIZE) == 0) {
            match++;
            break;
        }
        }
    }
    if (match == 0)
        continue;

    size_t denom = qcount + b->io.input_token_count - match;
    float jaccard = denom ? (float)match / (float)denom : 0.0f;

    /* Freshness (recent <=60s favored) */
    float age_sec = (float)((now > b->time.timestamp) ? (now - b->time.timestamp) : 0ULL) / 1e6f;
    float freshness = (age_sec < 60.0f) ? 1.0f : (60.0f / (age_sec + 60.0f));

    /* Weighted score */
    float weighted = jaccard
               * (0.5f + 0.5f * b->attributes.confidence)
               * (0.85f + 0.15f * freshness);

    if (weighted > best_score ||
        (weighted == best_score && best &&
         (b->attributes.confidence > best->attributes.confidence ||
          (b->attributes.confidence == best->attributes.confidence &&
           b->time.timestamp > best->time.timestamp)))) {
        best = b;
        best_score = weighted;
    }
    }

    return best;
}

/* ------------------------------- Diagnostics ------------------------------- */

void fossil_ai_jellyfish_dump(const fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) {
        printf("[jellyfish] (null chain)\n");
        return;
    }

    printf("=== Jellyfish Chain Dump ===\n");
    printf("RepoID: ");
    for (size_t i = 0; i < FOSSIL_DEVICE_ID_SIZE; ++i) printf("%02X", chain->repo_id[i]);
    printf("\nCreated: %llu  Updated: %llu\n",
           (unsigned long long)chain->created_at,
           (unsigned long long)chain->updated_at);
    printf("Branches (%zu):\n", chain->branch_count);
    for (size_t b = 0; b < chain->branch_count; ++b) {
        printf("  [%zu] %s head=", b, chain->branches[b].name);
        for (int i = 0; i < 8 && i < FOSSIL_JELLYFISH_HASH_SIZE; ++i)
            printf("%02X", chain->branches[b].head_hash[i]);
        printf("\n");
    }
    printf("Commits (count=%zu, capacity=%d)\n", chain->count, FOSSIL_JELLYFISH_MAX_MEM);

    /* Simple per-type counts */
    unsigned type_counts[64] = {0};
    size_t valid = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;
        valid++;
        if ((unsigned)b->block_type < 64)
            type_counts[b->block_type]++;
    }
    printf("Valid: %zu\n", valid);

    /* Print first N detailed commits (avoid huge spam) */
    const size_t DETAIL_LIMIT = 32;
    size_t printed = 0;
    for (size_t i = 0; i < chain->count && i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;
        if (printed == 0) printf("--- Commit Details (up to %zu) ---\n", DETAIL_LIMIT);
        if (printed >= DETAIL_LIMIT) {
            printf("... (%zu more not shown)\n", valid - printed);
            break;
        }
        char hash8[17] = {0};
        for (int k = 0; k < 8 && k < FOSSIL_JELLYFISH_HASH_SIZE; ++k)
            sprintf(hash8 + k * 2, "%02X", b->identity.commit_hash[k]);
        printf("#%04u %s type=%u conf=%.2f age=%llums I:\"%s\" -> O:\"%s\"\n",
               b->identity.commit_index,
               hash8,
               (unsigned)b->block_type,
               b->attributes.confidence,
               (unsigned long long)((get_time_microseconds() - b->time.timestamp)/1000ULL),
               b->io.input,
               b->io.output);
        printed++;
    }

    /* Type histogram (only non-zero) */
    printf("--- Type Histogram ---\n");
    for (unsigned t = 0; t < 64; ++t) {
        if (type_counts[t]) {
            printf(" type[%u]=%u\n", t, type_counts[t]);
        }
    }
    printf("=== End Dump ===\n");
}

void fossil_ai_jellyfish_reflect(const fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) {
        printf("[reflect] null chain\n");
        return;
    }

    uint64_t now = get_time_microseconds();

    size_t valid = 0, trusted = 0, immutable = 0;
    float conf_sum = 0.0f, conf_min = 1.0f, conf_max = 0.0f;
    uint64_t age_min_us = UINT64_MAX, age_max_us = 0, age_sum_us = 0;
    uint64_t newest_ts = 0, oldest_ts = UINT64_MAX;
    uint64_t usage_sum = 0;

    /* Confidence buckets 0..100 (percent) for O(C) percentile estimation */
    unsigned conf_buckets[101] = {0};

    /* Block type histogram (small) */
    unsigned type_hist[64] = {0};
    unsigned distinct_types = 0;

    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;

        valid++;

        float c = b->attributes.confidence;
        if (c < conf_min) conf_min = c;
        if (c > conf_max) conf_max = c;
        conf_sum += c;

        int bi = (int)(c * 100.0f + 0.5f);
        if (bi < 0) bi = 0;
        if (bi > 100) bi = 100;
        conf_buckets[bi]++;

        if (b->attributes.trusted)   trusted++;
        if (b->attributes.immutable) immutable++;

        if ((unsigned)b->block_type < 64) {
            if (type_hist[b->block_type] == 0) distinct_types++;
            type_hist[b->block_type]++;
        }

        uint64_t ts = b->time.timestamp;
        if (ts > newest_ts) newest_ts = ts;
        if (ts < oldest_ts) oldest_ts = ts;

        uint64_t age_us = (now > ts) ? (now - ts) : 0;
        if (age_us < age_min_us) age_min_us = age_us;
        if (age_us > age_max_us) age_max_us = age_us;
        age_sum_us += age_us;

        usage_sum += b->attributes.usage_count;
    }

    if (valid == 0) {
        printf("[reflect] empty (capacity=%d)\n", FOSSIL_JELLYFISH_MAX_MEM);
        return;
    }

    /* Percentiles from bucket scan */
    unsigned long cumulative = 0;
    size_t p50 = 0, p90 = 0, p99 = 0;
    size_t t50 = (size_t)(0.50 * valid);
    size_t t90 = (size_t)(0.90 * valid);
    size_t t99 = (size_t)(0.99 * valid);
    if (t50 >= valid) t50 = valid - 1;
    if (t90 >= valid) t90 = valid - 1;
    if (t99 >= valid) t99 = valid - 1;

    for (int b = 0; b <= 100; ++b) {
        cumulative += conf_buckets[b];
        if (cumulative && cumulative - conf_buckets[b] <= t50 && cumulative > t50) p50 = b;
        if (cumulative && cumulative - conf_buckets[b] <= t90 && cumulative > t90) p90 = b;
        if (cumulative && cumulative - conf_buckets[b] <= t99 && cumulative > t99) p99 = b;
    }

    float avg_conf = conf_sum / (float)valid;
    double avg_age_s = (double)age_sum_us / (double)valid / 1e6;
    double age_min_s = (age_min_us == UINT64_MAX) ? 0.0 : (double)age_min_us / 1e6;
    double age_max_s = (double)age_max_us / 1e6;
    double coverage = (double)valid / (double)FOSSIL_JELLYFISH_MAX_MEM;
    double trusted_ratio = (double)trusted / (double)valid;
    double immutable_ratio = (double)immutable / (double)valid;
    double mean_usage = (double)usage_sum / (double)valid;

    printf("[reflect] valid=%zu capacity=%d coverage=%.2f%% distinct_types=%u\n",
           valid, FOSSIL_JELLYFISH_MAX_MEM, coverage * 100.0, distinct_types);
    printf("[reflect] confidence avg=%.3f min=%.3f max=%.3f p50=%.2f%% p90=%.2f%% p99=%.2f%%\n",
           avg_conf, conf_min, conf_max, (float)p50, (float)p90, (float)p99);
    printf("[reflect] age avg=%.2fs min=%.2fs max=%.2fs newest_age=%.2fms oldest_age=%.2fs\n",
           avg_age_s, age_min_s, age_max_s,
           (newest_ts ? (double)((now > newest_ts ? now - newest_ts : 0) / 1000.0) : 0.0),
           (oldest_ts ? (double)((now > oldest_ts ? now - oldest_ts : 0) / 1e6) : 0.0));
    printf("[reflect] trusted=%zu (%.2f%%) immutable=%zu (%.2f%%) mean_usage=%.2f\n",
           trusted, trusted_ratio * 100.0, immutable, immutable_ratio * 100.0, mean_usage);

    /* Optional small type histogram (only non-zero) */
    printf("[reflect] type_hist:");
    for (unsigned t = 0; t < 64; ++t) {
        if (type_hist[t])
            printf(" %u:%u", t, type_hist[t]);
    }
    printf("\n");
}

void fossil_ai_jellyfish_validation_report(const fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) {
        printf("[validate] null chain\n");
        return;
    }

    /* Gather valid hashes for parent existence checks */
    uint8_t valid_hashes[FOSSIL_JELLYFISH_MAX_MEM][FOSSIL_JELLYFISH_HASH_SIZE];
    size_t  valid_count = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (b->attributes.valid) {
            memcpy(valid_hashes[valid_count], b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);
            valid_count++;
        }
    }

    size_t scanned = 0;
    size_t anomalies_total = 0;

    printf("=== Jellyfish Validation Report ===\n");
    printf("Idx  Hash(8) Type Conf  Anom  Msg\n");

    for (size_t i = 0; i < chain->count && i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;
        scanned++;

        char hash8[17] = {0};
        for (int k = 0; k < 8 && k < FOSSIL_JELLYFISH_HASH_SIZE; ++k)
            sprintf(hash8 + k*2, "%02X", b->identity.commit_hash[k]);

        char anom[16];
        int ap = 0;

        /* Recompute hash */
        uint8_t recomputed[FOSSIL_JELLYFISH_HASH_SIZE];
        fossil_ai_jellyfish_hash(b->io.input, b->io.output, recomputed);
        if (memcmp(recomputed, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE) != 0 &&
            ap < (int)sizeof(anom)-1) anom[ap++]='H';

        /* Zero hash */
        int all_zero = 1;
        for (size_t z=0; z<FOSSIL_JELLYFISH_HASH_SIZE; ++z)
            if (b->identity.commit_hash[z]) { all_zero=0; break; }
        if (all_zero && ap < (int)sizeof(anom)-1) anom[ap++]='Z';

        /* Parent count / merge flag consistency */
        if (b->identity.parent_count > 4 ||
            (b->identity.parent_count >=2 && !b->identity.is_merge_commit) ||
            (b->identity.parent_count < 2 && b->identity.is_merge_commit)) {
            if (ap < (int)sizeof(anom)-1) anom[ap++]='C';
        }

        /* Parent existence */
        for (size_t p = 0; p < b->identity.parent_count && p < 4; ++p) {
            int found = 0;
            for (size_t vh = 0; vh < valid_count; ++vh) {
                if (memcmp(valid_hashes[vh], b->identity.parent_hashes[p], FOSSIL_JELLYFISH_HASH_SIZE) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) {
                if (ap < (int)sizeof(anom)-1) anom[ap++]='P';
                break;
            }
        }

        /* Signed commit must have signature */
        if (b->block_type == JELLY_COMMIT_SIGNED && b->identity.signature_len == 0) {
            if (ap < (int)sizeof(anom)-1) anom[ap++]='S';
        }

        /* Confidence range */
        if (b->attributes.confidence < 0.0f || b->attributes.confidence > 1.0f) {
            if (ap < (int)sizeof(anom)-1) anom[ap++]='F';
        }

        anom[ap] = '\0';
        if (ap) anomalies_total++;

        /* Commit message (truncate) */
        char msg[33];
        if (b->identity.commit_message[0]) {
            strncpy(msg, b->identity.commit_message, 32);
            msg[32]='\0';
        } else {
            strcpy(msg, "-");
        }

        printf("%-4u %s  %3u  %0.3f  %-5s %s\n",
               b->identity.commit_index,
               hash8,
               (unsigned)b->block_type,
               b->attributes.confidence,
               ap?anom:"-",
               msg);
    }

    printf("Summary: valid=%zu scanned=%zu anomalies=%zu (%.2f%%)\n",
           valid_count,
           scanned,
           anomalies_total,
           scanned? (100.0 * (double)anomalies_total / (double)scanned):0.0);
    printf("=== End Validation Report ===\n");
}

bool fossil_ai_jellyfish_verify_chain(const fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return false;

    /* Collect valid commit hashes */
    uint8_t hashes[FOSSIL_JELLYFISH_MAX_MEM][FOSSIL_JELLYFISH_HASH_SIZE];
    size_t  idx_map[FOSSIL_JELLYFISH_MAX_MEM];
    size_t  vcount = 0;

    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;

        /* Basic index consistency */
        if (b->identity.commit_index != i) return false;

        /* Zero hash disallowed */
        int all_zero = 1;
        for (size_t k = 0; k < FOSSIL_JELLYFISH_HASH_SIZE; ++k)
            if (b->identity.commit_hash[k] != 0) { all_zero = 0; break; }
        if (all_zero) return false;

        /* Uniqueness (linear scan – small bound) */
        for (size_t p = 0; p < vcount; ++p)
            if (memcmp(hashes[p], b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE) == 0)
                return false;

        memcpy(hashes[vcount], b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);
        idx_map[vcount] = i;
        vcount++;
    }

    /* Per-block deep checks */
    for (size_t vi = 0; vi < vcount; ++vi) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[idx_map[vi]];

        /* Recompute hash (content addressing) */
        uint8_t recomputed[FOSSIL_JELLYFISH_HASH_SIZE];
        fossil_ai_jellyfish_hash(b->io.input, b->io.output, recomputed);
        if (memcmp(recomputed, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE) != 0)
            return false;

        /* Parent constraints */
        if (b->identity.parent_count > 4) return false;
        if ((b->identity.parent_count >= 2 && !b->identity.is_merge_commit) ||
            (b->identity.parent_count < 2 && b->identity.is_merge_commit))
            return false;

        for (size_t p = 0; p < b->identity.parent_count; ++p) {
            int found = 0;
            /* Parent must exist among valid hashes and not be self */
            if (memcmp(b->identity.parent_hashes[p],
                       b->identity.commit_hash,
                       FOSSIL_JELLYFISH_HASH_SIZE) == 0)
                return false;
            for (size_t vh = 0; vh < vcount; ++vh) {
                if (memcmp(hashes[vh], b->identity.parent_hashes[p], FOSSIL_JELLYFISH_HASH_SIZE) == 0) {
                    found = 1;
                    break;
                }
            }
            if (!found) return false;
        }

        /* Signed commit must have signature */
        if (b->block_type == JELLY_COMMIT_SIGNED && b->identity.signature_len == 0)
            return false;

        /* Length integrity */
        if (b->io.input_len != strnlen(b->io.input, FOSSIL_JELLYFISH_INPUT_SIZE)) return false;
        if (b->io.output_len != strnlen(b->io.output, FOSSIL_JELLYFISH_OUTPUT_SIZE)) return false;

        /* Confidence bounds */
        if (b->attributes.confidence < 0.0f || b->attributes.confidence > 1.0f) return false;
    }

    /* Branch head validity */
    for (size_t br = 0; br < chain->branch_count; ++br) {
        const uint8_t *head = chain->branches[br].head_hash;
        int all_zero = 1;
        for (size_t k = 0; k < FOSSIL_JELLYFISH_HASH_SIZE; ++k)
            if (head[k]) { all_zero = 0; break; }
        if (all_zero) continue; /* allow empty head */

        int found = 0;
        for (size_t vh = 0; vh < vcount; ++vh) {
            if (memcmp(hashes[vh], head, FOSSIL_JELLYFISH_HASH_SIZE) == 0) { found = 1; break; }
        }
        if (!found) return false;
    }

    return true;
}

bool fossil_ai_jellyfish_verify_block(const fossil_ai_jellyfish_block_t *block) {
    if (!block) return false;

    /* 1. Hash integrity */
    uint8_t recomputed[FOSSIL_JELLYFISH_HASH_SIZE];
    fossil_ai_jellyfish_hash(block->io.input, block->io.output, recomputed);
    if (memcmp(recomputed, block->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE) != 0)
        return false;

    /* 2. Non-zero hash */
    int all_zero = 1;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_HASH_SIZE; ++i)
        if (block->identity.commit_hash[i]) { all_zero = 0; break; }
    if (all_zero) return false;

    /* 3. Parent constraints */
    if (block->identity.parent_count > 4) return false;
    if ((block->identity.parent_count >= 2 && !block->identity.is_merge_commit) ||
        (block->identity.parent_count < 2 && block->identity.is_merge_commit))
        return false;
    for (size_t p = 0; p < block->identity.parent_count; ++p) {
        if (memcmp(block->identity.parent_hashes[p],
                   block->identity.commit_hash,
                   FOSSIL_JELLYFISH_HASH_SIZE) == 0)
            return false; /* self-parent disallowed */
        int ph_zero = 1;
        for (size_t b = 0; b < FOSSIL_JELLYFISH_HASH_SIZE; ++b)
            if (block->identity.parent_hashes[p][b]) { ph_zero = 0; break; }
        if (ph_zero) return false; /* zero parent hash */
    }

    /* 4. Merge type semantics */
    if (block->block_type == JELLY_COMMIT_MERGE && block->identity.parent_count < 2)
        return false;

    /* 5. Signed commit requires signature */
    if (block->block_type == JELLY_COMMIT_SIGNED) {
        if (block->identity.signature_len == 0 ||
            block->identity.signature_len > FOSSIL_SIGNATURE_SIZE)
            return false;
    } else {
        if (block->identity.signature_len > FOSSIL_SIGNATURE_SIZE)
            return false;
    }

    /* 6. IO length integrity */
    size_t in_len  = strnlen(block->io.input, FOSSIL_JELLYFISH_INPUT_SIZE);
    size_t out_len = strnlen(block->io.output, FOSSIL_JELLYFISH_OUTPUT_SIZE);
    if (in_len != block->io.input_len) return false;
    if (out_len != block->io.output_len) return false;
    if (in_len >= FOSSIL_JELLYFISH_INPUT_SIZE) return false;
    if (out_len >= FOSSIL_JELLYFISH_OUTPUT_SIZE) return false;

    /* 7. Token bounds */
    if (block->io.input_token_count > FOSSIL_JELLYFISH_MAX_TOKENS) return false;
    if (block->io.output_token_count > FOSSIL_JELLYFISH_MAX_TOKENS) return false;

    /* 8. Confidence bounds */
    if (block->attributes.confidence < 0.0f || block->attributes.confidence > 1.0f)
        return false;

    /* 9. Basic block_type sanity (enum range) */
    if (block->block_type < JELLY_COMMIT_UNKNOWN || block->block_type > JELLY_COMMIT_FINAL)
        return false;

    return true;
}

float fossil_ai_jellyfish_chain_trust_score(const fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return 0.0f;

    float accum = 0.0f;
    float wsum  = 0.0f;

    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;
        if (b->attributes.pruned || b->attributes.expired) continue; /* exclude removed/expired */

        float w = 1.0f;

        /* usage weight ~ log2 via shifts (cheap) */
        uint32_t u = b->attributes.usage_count;
        int lg = 0;
        while (u > 1) { u >>= 1; lg++; }
        w += 0.10f * (float)lg;

        if (b->attributes.trusted)    w += 0.75f;
        if (b->attributes.immutable)  w += 0.25f;

        switch (b->block_type) {
            case JELLY_COMMIT_VALIDATE:
            case JELLY_COMMIT_SIGNED:   w += 0.50f; break;
            case JELLY_COMMIT_RELEASE:
            case JELLY_COMMIT_TAG:      w += 0.40f; break;
            case JELLY_COMMIT_PATCH:    w += 0.20f; break;
            case JELLY_COMMIT_DRAFT:
            case JELLY_COMMIT_EXPERIMENT:
            case JELLY_COMMIT_STASH:    w *= 0.70f; break;
            default: break;
        }

        if (b->attributes.redacted)   w *= 0.85f;
        if (b->attributes.conflicted) w *= 0.50f;

        float c = b->attributes.confidence;
        if (c < 0.0f) c = 0.0f;
        if (c > 1.0f) c = 1.0f;

        accum += c * w;
        wsum  += w;
    }

    if (wsum <= 0.0f) return 0.0f;

    float score = accum / wsum;
    if (score < 0.0f) score = 0.0f;
    if (score > 1.0f) score = 1.0f;
    return score;
}

void fossil_ai_jellyfish_chain_fingerprint(const fossil_ai_jellyfish_chain_t *chain, uint8_t *out_hash) {
    if (!out_hash) return;
    memset(out_hash, 0, FOSSIL_JELLYFISH_HASH_SIZE);
    if (!chain) return;

    const uint64_t PRIME = 0x100000001b3ULL;
    uint64_t acc[4] = {
        0x0123456789abcdefULL ^ chain->created_at,
        0xfedcba9876543210ULL ^ chain->updated_at,
        0x0f1e2d3c4b5a6978ULL ^ ((uint64_t)chain->branch_count << 48),
        0x8877665544332211ULL ^ ((uint64_t)FOSSIL_JELLYFISH_MAX_MEM << 32)
    };

    /* Fold repo_id deterministically */
    for (size_t i = 0; i < FOSSIL_DEVICE_ID_SIZE; ++i) {
        uint8_t b = chain->repo_id[i];
        acc[i & 3] ^= ((uint64_t)SBOX[b] << ((i & 7) * 8)) ^ ((uint64_t)b * PRIME);
    }

    size_t valid_count = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;
        valid_count++;

        /* Consume 32-byte commit hash as four little-endian 64-bit words */
        for (int k = 0; k < 4; ++k) {
            uint64_t word = 0;
            const uint8_t *hp = b->identity.commit_hash + (k * 8);
            for (int j = 0; j < 8; ++j)
                word |= (uint64_t)hp[j] << (j * 8);

            /* Order-independent contribution f(h) XORed into accumulator */
            uint8_t sidx = hp[(k * 7 + 13) & 7]; /* small variation */
            uint64_t mix = word * PRIME;
            mix ^= (uint64_t)SBOX[sidx] << 56;
            mix ^= (uint64_t)k << 52;
            mix ^= (uint64_t)(b->block_type & 0xFF) << (8 * (k & 7));
            acc[k] ^= mix;
        }
    }

    /* Incorporate counts (commutative) */
    acc[0] ^= ((uint64_t)valid_count << 32) ^ (uint64_t)valid_count * PRIME;
    acc[1] ^= ((uint64_t)chain->count << 24) ^ ((uint64_t)FOSSIL_JELLYFISH_MAX_MEM * PRIME);
    acc[2] ^= ((uint64_t)chain->branch_count << 40);
    acc[3] ^= ((uint64_t)(valid_count ^ chain->branch_count) * 0x9e3779b185ebca87ULL);

    /* Final avalanche (non-commutative but applied after commutative phase) */
    for (int r = 0; r < 4; ++r) {
        acc[r] ^= ROTL64(acc[(r + 1) & 3] * PRIME, 17 + r);
        acc[r] *= 0x9e3779b185ebca87ULL;
        acc[r] ^= ROTL64(acc[(r + 2) & 3], 21 - r);
        acc[r] *= PRIME;
        acc[r] ^= acc[(r + 3) & 3] >> (7 + r);
    }

    /* Light SBOX whitening */
    for (int k = 0; k < 4; ++k) {
        uint64_t v = acc[k];
        uint64_t w = 0;
        for (int b = 0; b < 8; ++b) {
            uint8_t byte = (uint8_t)((v >> (b * 8)) & 0xFF);
            byte = SBOX[byte];
            w |= (uint64_t)byte << (b * 8);
        }
        acc[k] = w ^ ROTL64(v, (k * 11 + 13) & 63);
    }

    /* Serialize little-endian into out_hash */
    for (int k = 0; k < 4; ++k) {
        uint64_t v = acc[k];
        for (int b = 0; b < 8; ++b) {
            out_hash[k * 8 + b] = (uint8_t)(v >> (b * 8));
        }
    }
}

void fossil_ai_jellyfish_chain_stats(const fossil_ai_jellyfish_chain_t *chain,
                                     size_t out_valid_count[5],
                                     float  out_avg_confidence[5],
                                     float  out_immutable_ratio[5])
{
    /* Groups:
       0: Core (0..9)
       1: Branching / Merging (10..19)
       2: Tagging / Release / Archive (20..29)
       3: Experimental / Ephemeral (30..39)
       4: Collaboration + Special / Terminal (>=40)
    */
    if (out_valid_count)      memset(out_valid_count, 0, sizeof(size_t)*5);
    if (out_avg_confidence)   memset(out_avg_confidence, 0, sizeof(float)*5);
    if (out_immutable_ratio)  memset(out_immutable_ratio, 0, sizeof(float)*5);
    if (!chain) return;

    size_t immut_count[5] = {0};
    float  conf_sum[5]    = {0.0f};

    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;

        int t = (int)b->block_type;
        int g;
        if      (t >= 0  && t <= 9)   g = 0;
        else if (t >= 10 && t <= 19)  g = 1;
        else if (t >= 20 && t <= 29)  g = 2;
        else if (t >= 30 && t <= 39)  g = 3;
        else                          g = 4;

        if (g < 0 || g > 4) g = 4;

        out_valid_count[g]++;
        conf_sum[g] += (b->attributes.confidence < 0.0f) ? 0.0f :
                       (b->attributes.confidence > 1.0f) ? 1.0f :
                        b->attributes.confidence;
        if (b->attributes.immutable) immut_count[g]++;
    }

    if (out_avg_confidence) {
        for (int g = 0; g < 5; ++g) {
            out_avg_confidence[g] = out_valid_count[g] ?
                                    (conf_sum[g] / (float)out_valid_count[g]) : 0.0f;
        }
    }
    if (out_immutable_ratio) {
        for (int g = 0; g < 5; ++g) {
            out_immutable_ratio[g] = out_valid_count[g] ?
                                     (float)immut_count[g] / (float)out_valid_count[g] : 0.0f;
        }
    }
}

int fossil_ai_jellyfish_compare_chains(const fossil_ai_jellyfish_chain_t *a,
                                       const fossil_ai_jellyfish_chain_t *b) {
    if (!a || !b) return -1;

    size_t max_slots = FOSSIL_JELLYFISH_MAX_MEM;
    if (a->count > max_slots) max_slots = FOSSIL_JELLYFISH_MAX_MEM;
    if (b->count > max_slots) max_slots = FOSSIL_JELLYFISH_MAX_MEM; /* bounded anyway */

    int diff = 0;

    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *A = &a->commits[i];
        const fossil_ai_jellyfish_block_t *B = &b->commits[i];

        int Avalid = A->attributes.valid;
        int Bvalid = B->attributes.valid;

        /* Case: validity mismatch */
        if (Avalid != Bvalid) {
            diff++;
            continue;
        }

        if (!Avalid) {
            /* both invalid -> ignore */
            continue;
        }

        /* Both valid: first compare commit hash */
        if (memcmp(A->identity.commit_hash, B->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE) != 0) {
            diff++;
            continue;
        }

        /* Same hash (input+output identical). Check semantic deltas. */
        int semantic_changed = 0;

        /* Commit type */
        if (A->block_type != B->block_type)
            semantic_changed = 1;

        /* IO compressed/redacted flags (contents already implied by hash) */
        if (!semantic_changed &&
            (A->io.compressed != B->io.compressed ||
             A->io.redacted   != B->io.redacted))
            semantic_changed = 1;

        /* Attributes (allow tiny float noise) */
        if (!semantic_changed) {
            float ca = A->attributes.confidence;
            float cb = B->attributes.confidence;
            if ((ca - cb > 0.0001f) || (cb - ca > 0.0001f) ||
                A->attributes.immutable    != B->attributes.immutable ||
                A->attributes.pruned       != B->attributes.pruned ||
                A->attributes.redacted     != B->attributes.redacted ||
                A->attributes.deduplicated != B->attributes.deduplicated ||
                A->attributes.compressed   != B->attributes.compressed ||
                A->attributes.expired      != B->attributes.expired ||
                A->attributes.trusted      != B->attributes.trusted ||
                A->attributes.conflicted   != B->attributes.conflicted ||
                A->attributes.usage_count  != B->attributes.usage_count)
                semantic_changed = 1;
        }

        /* Classification reason */
        if (!semantic_changed &&
            strncmp(A->classify.classification_reason,
                    B->classify.classification_reason,
                    sizeof(A->classify.classification_reason)) != 0)
            semantic_changed = 1;

        /* Tags */
        if (!semantic_changed &&
            memcmp(A->classify.tags, B->classify.tags, sizeof(A->classify.tags)) != 0)
            semantic_changed = 1;

        /* Similarity / flags */
        if (!semantic_changed &&
            (A->classify.similarity_score != B->classify.similarity_score ||
             A->classify.is_hallucinated  != B->classify.is_hallucinated ||
             A->classify.is_contradicted  != B->classify.is_contradicted))
            semantic_changed = 1;

        /* Parent list (hash already same, but ancestry could differ logically) */
        if (!semantic_changed) {
            if (A->identity.parent_count != B->identity.parent_count) {
                semantic_changed = 1;
            } else if (A->identity.parent_count) {
                if (memcmp(A->identity.parent_hashes, B->identity.parent_hashes,
                           A->identity.parent_count * FOSSIL_JELLYFISH_HASH_SIZE) != 0)
                    semantic_changed = 1;
            }
        }

        /* Commit metadata fields (message, merge flag, detached, branch id) */
        if (!semantic_changed &&
            (A->identity.is_merge_commit != B->identity.is_merge_commit ||
             A->identity.detached        != B->identity.detached ||
             A->identity.branch_id       != B->identity.branch_id ||
             strncmp(A->identity.commit_message,
                     B->identity.commit_message,
                     sizeof(A->identity.commit_message)) != 0))
            semantic_changed = 1;

        if (semantic_changed)
            diff++;
    }

    return diff;
}

uint64_t fossil_ai_jellyfish_block_age(const fossil_ai_jellyfish_block_t *block, uint64_t now) {
    if (!block) return 0;
    uint64_t ts = block->time.timestamp;
    if (ts == 0) {
        /* Fallback: updated_at if timestamp not set */
        ts = block->time.updated_at;
    }
    if (ts == 0 || now <= ts)
        return 0;
    return now - ts;
}

void fossil_ai_jellyfish_block_explain(const fossil_ai_jellyfish_block_t *block, char *out, size_t size) {
    if (!out || size == 0) return;
    if (!block) {
        if (size) { out[0] = '\0'; }
        return;
    }

    /* Map commit type to short name */
    const char *type = "UNKNOWN";
    switch (block->block_type) {
        case JELLY_COMMIT_UNKNOWN: type = "UNKNOWN"; break;
        case JELLY_COMMIT_INIT: type = "INIT"; break;
        case JELLY_COMMIT_OBSERVE: type = "OBSERVE"; break;
        case JELLY_COMMIT_INFER: type = "INFER"; break;
        case JELLY_COMMIT_VALIDATE: type = "VALIDATE"; break;
        case JELLY_COMMIT_PATCH: type = "PATCH"; break;
        case JELLY_COMMIT_BRANCH: type = "BRANCH"; break;
        case JELLY_COMMIT_MERGE: type = "MERGE"; break;
        case JELLY_COMMIT_REBASE: type = "REBASE"; break;
        case JELLY_COMMIT_CHERRY_PICK: type = "CHERRY"; break;
        case JELLY_COMMIT_FORK: type = "FORK"; break;
        case JELLY_COMMIT_TAG: type = "TAG"; break;
        case JELLY_COMMIT_RELEASE: type = "RELEASE"; break;
        case JELLY_COMMIT_ARCHIVE: type = "ARCHIVE"; break;
        case JELLY_COMMIT_SNAPSHOT: type = "SNAP"; break;
        case JELLY_COMMIT_EXPERIMENT: type = "EXPER"; break;
        case JELLY_COMMIT_STASH: type = "STASH"; break;
        case JELLY_COMMIT_DRAFT: type = "DRAFT"; break;
        case JELLY_COMMIT_REVERT: type = "REVERT"; break;
        case JELLY_COMMIT_ROLLBACK: type = "ROLLBACK"; break;
        case JELLY_COMMIT_SYNC: type = "SYNC"; break;
        case JELLY_COMMIT_MIRROR: type = "MIRROR"; break;
        case JELLY_COMMIT_IMPORT: type = "IMPORT"; break;
        case JELLY_COMMIT_EXPORT: type = "EXPORT"; break;
        case JELLY_COMMIT_SIGNED: type = "SIGNED"; break;
        case JELLY_COMMIT_REVIEW: type = "REVIEW"; break;
        case JELLY_COMMIT_DETACHED: type = "DETACHED"; break;
        case JELLY_COMMIT_ABANDONED: type = "ABANDON"; break;
        case JELLY_COMMIT_CONFLICT: type = "CONFLICT"; break;
        case JELLY_COMMIT_PRUNE: type = "PRUNE"; break;
        case JELLY_COMMIT_FINAL: type = "FINAL"; break;
        default: break;
    }

    /* Prepare truncated IO samples */
    char in[17]; char outv[17];
    size_t il = strnlen(block->io.input, sizeof(block->io.input));
    size_t ol = strnlen(block->io.output, sizeof(block->io.output));
    if (il > 15) { memcpy(in, block->io.input, 12); memcpy(in+12, "...", 4); }
    else { memcpy(in, block->io.input, il); in[il] = '\0'; }
    if (ol > 15) { memcpy(outv, block->io.output, 12); memcpy(outv+12, "...", 4); }
    else { memcpy(outv, block->io.output, ol); outv[ol] = '\0'; }

    /* Flags string (sparse) */
    char flags[32]; size_t fp = 0;
    if (block->attributes.valid)        flags[fp++]='V';
    if (block->attributes.immutable)    flags[fp++]='I';
    if (block->attributes.trusted)      flags[fp++]='T';
    if (block->attributes.redacted)     flags[fp++]='R';
    if (block->io.compressed || block->attributes.compressed) flags[fp++]='C';
    if (block->attributes.deduplicated) flags[fp++]='D';
    if (block->attributes.conflicted)   flags[fp++]='X';
    if (block->attributes.pruned)       flags[fp++]='P';
    if (block->attributes.expired)      flags[fp++]='E';
    flags[fp] = '\0';
    if (fp == 0) { flags[fp++]='-'; flags[fp]='\0'; }

    /* First 4 bytes of hash for brevity */
    char h8[9];
    for (int i = 0; i < 4; ++i) sprintf(h8 + i*2, "%02X", block->identity.commit_hash[i]);
    h8[8]='\0';

    snprintf(out, size,
             "#%04u %s h=%s conf=%.2f pc=%zu %s I:\"%s\" O:\"%s\"",
             block->identity.commit_index,
             type,
             h8,
             (block->attributes.confidence < 0.0f)?0.0f:
             (block->attributes.confidence>1.0f)?1.0f:block->attributes.confidence,
             block->identity.parent_count,
             flags,
             in[0]?in:"-",
             outv[0]?outv:"-");
}

/* ----------------------------- Optimization -------------------------------- */

void fossil_ai_jellyfish_decay_confidence(fossil_ai_jellyfish_chain_t *chain, float decay_rate) {
    if (!chain) return;
    if (decay_rate <= 0.0f) return;
    if (decay_rate >= 1.0f) {
        /* Full decay => zero out (respect immutability) */
        for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
            fossil_ai_jellyfish_block_t *b = &chain->commits[i];
            if (!b->attributes.valid) continue;
            if (b->attributes.immutable) continue;
            b->attributes.confidence = 0.0f;
        }
        chain->updated_at = get_time_microseconds();
        return;
    }

    float factor = 1.0f - decay_rate;
    if (factor < 0.0f) factor = 0.0f;
    if (factor > 1.0f) factor = 1.0f;

    int any = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;
        if (b->attributes.immutable) continue; /* preserve immutable confidence */
        float c = b->attributes.confidence;
        if (c <= 0.0f) continue;
        c *= factor;
        if (c < 0.0001f) c = 0.0f;
        if (c > 1.0f)   c = 1.0f;
        b->attributes.confidence = c;
        any = 1;
    }

    if (any)
        chain->updated_at = get_time_microseconds();
}

int fossil_ai_jellyfish_trim(fossil_ai_jellyfish_chain_t *chain, size_t max_blocks) {
    if (!chain) return 0;

    /* Gather valid blocks */
    struct candidate {
        size_t index;
        float  confidence;
        uint64_t timestamp;
        int immutable;
    } cand[FOSSIL_JELLYFISH_MAX_MEM];

    size_t valid_count = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;
        cand[valid_count].index = i;
        cand[valid_count].confidence = (b->attributes.confidence < 0.0f) ? 0.0f :
                                       (b->attributes.confidence > 1.0f) ? 1.0f :
                                        b->attributes.confidence;
        cand[valid_count].timestamp = b->time.timestamp;
        cand[valid_count].immutable = b->attributes.immutable;
        valid_count++;
    }

    if (valid_count <= max_blocks) return 0;

    size_t keep_target = max_blocks;
    size_t remove_needed = valid_count - keep_target;

    /* Separate mutable candidates */
    struct candidate mut[FOSSIL_JELLYFISH_MAX_MEM];
    size_t mut_count = 0;
    for (size_t i = 0; i < valid_count; ++i) {
        if (!cand[i].immutable) {
            mut[mut_count++] = cand[i];
        }
    }
    if (mut_count == 0) return 0; /* Nothing we are allowed to trim */

    /* Sort mutable candidates ascending (worst first) by:
       1) confidence (low first)
       2) timestamp (older first)
       3) higher index last (prefer pruning higher indices slightly) */
    for (size_t i = 0; i < mut_count; ++i) {
        for (size_t j = i + 1; j < mut_count; ++j) {
            int swap = 0;
            if (mut[j].confidence < mut[i].confidence) swap = 1;
            else if (mut[j].confidence == mut[i].confidence) {
                if (mut[j].timestamp < mut[i].timestamp) swap = 1;
                else if (mut[j].timestamp == mut[i].timestamp &&
                         mut[j].index > mut[i].index) swap = 1;
            }
            if (swap) {
                struct candidate tmp = mut[i];
                mut[i] = mut[j];
                mut[j] = tmp;
            }
        }
    }

    size_t to_remove = remove_needed;
    if (to_remove > mut_count) to_remove = mut_count;

    int pruned = 0;
    uint64_t now = get_time_microseconds();

    for (size_t k = 0; k < to_remove; ++k) {
        fossil_ai_jellyfish_block_t *b = &chain->commits[mut[k].index];
        if (!b->attributes.valid || b->attributes.immutable) continue;
        b->attributes.valid = 0;
        b->attributes.pruned = 1;
        b->attributes.confidence = 0.0f;
        b->block_type = JELLY_COMMIT_PRUNE;
        b->time.expires_at = now;

        /* Clear branch heads pointing here */
        for (size_t br = 0; br < chain->branch_count; ++br) {
            if (memcmp(chain->branches[br].head_hash,
                       b->identity.commit_hash,
                       FOSSIL_JELLYFISH_HASH_SIZE) == 0) {
                memset(chain->branches[br].head_hash, 0, FOSSIL_JELLYFISH_HASH_SIZE);
            }
        }
        pruned++;
        if (pruned >= (int)to_remove) break;
    }

    if (pruned) {
        fossil_ai_jellyfish_cleanup(chain);
    }

    return pruned;
}

int fossil_ai_jellyfish_chain_compact(fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return 0;

    size_t write = 0;
    int moved = 0;

    for (size_t read = 0; read < FOSSIL_JELLYFISH_MAX_MEM; ++read) {
        if (!chain->commits[read].attributes.valid)
            continue;

        if (read != write) {
            chain->commits[write] = chain->commits[read]; /* struct copy */
            chain->commits[write].identity.commit_index = (uint32_t)write;
            moved++;
        } else {
            /* Ensure index consistency even if not moved */
            chain->commits[write].identity.commit_index = (uint32_t)write;
        }
        write++;
    }

    /* Clear remaining slots */
    for (size_t i = write; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        memset(&chain->commits[i], 0, sizeof(chain->commits[i]));
    }

    chain->count = write;
    chain->updated_at = get_time_microseconds();
    return moved;
}

int fossil_ai_jellyfish_deduplicate_chain(fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return 0;
    int deduped = 0;
    size_t upper = chain->count;
    if (upper > FOSSIL_JELLYFISH_MAX_MEM) upper = FOSSIL_JELLYFISH_MAX_MEM;

    for (size_t i = 0; i < upper; ++i) {
        fossil_ai_jellyfish_block_t *a = &chain->commits[i];
        if (!a->attributes.valid) continue;

        for (size_t j = i + 1; j < upper; ++j) {
            fossil_ai_jellyfish_block_t *b = &chain->commits[j];
            if (!b->attributes.valid) continue;

            // Compare input/output strings
            if (strcmp(a->io.input, b->io.input) == 0 &&
                strcmp(a->io.output, b->io.output) == 0) {
                // Retain higher confidence, or earlier if equal
                int keep_a = (a->attributes.confidence > b->attributes.confidence) ||
                             (a->attributes.confidence == b->attributes.confidence &&
                              a->time.timestamp <= b->time.timestamp);

                fossil_ai_jellyfish_block_t *remove = keep_a ? b : a;
                remove->attributes.valid = 0;
                remove->attributes.deduplicated = 1;
                remove->attributes.confidence = 0.0f;
                remove->block_type = JELLY_COMMIT_PRUNE;
                remove->time.expires_at = get_time_microseconds();
                deduped++;
                // If we removed a, break inner loop and continue with next i
                if (!keep_a) break;
            }
        }
    }
    if (deduped) fossil_ai_jellyfish_cleanup(chain);
    return deduped;
}

/**
 * Internal helper: in-place whitespace normalization for an IO field.
 * - Trims leading/trailing ASCII whitespace.
 * - Collapses internal runs of whitespace (space, tab, CR, LF, etc.) to a single space.
 * - Removes control chars (<32 except TAB treated as space).
 * Returns 1 if buffer modified, 0 otherwise.
 */
static int fossil_ai_jellyfish_compress_io_field(char *buf, size_t cap) {
    if (!buf || cap == 0) return 0;

    size_t orig_len = strnlen(buf, cap);
    if (orig_len == 0 || orig_len >= cap) return 0; /* Nothing or already full (leave) */

    const unsigned char *src = (const unsigned char *)buf;
    char tmp[FOSSIL_JELLYFISH_OUTPUT_SIZE]; /* largest of input/output sizes (both 64) */
    if (cap > sizeof(tmp)) cap = sizeof(tmp); /* safety clamp */

    size_t s = 0;

    /* Skip leading whitespace */
    while (s < orig_len && isspace(src[s])) s++;

    int changed = 0;
    size_t d = 0;
    int in_space = 0;

    for (; s < orig_len && d + 1 < cap; ++s) {
        unsigned char c = src[s];

        if (isspace(c)) {
            in_space = 1;
            continue;
        }

        /* Emit single space if we were in a whitespace run and not at start */
        if (in_space && d > 0) {
            if (tmp[d] != ' ') { /* just for change detection */
                tmp[d++] = ' ';
            } else {
                d++; /* space already there analytically (shouldn't happen) */
            }
        }
        in_space = 0;

        /* Filter control characters (keep printable ASCII 32..126) */
        if (c < 32 || c == 127) {
            changed = 1;
            continue;
        }

        tmp[d++] = (char)c;
    }

    /* Remove trailing space if last emitted is space */
    if (d > 0 && tmp[d - 1] == ' ')
        d--;

    tmp[d] = '\0';

    if (!changed) {
        /* Detect differences vs original */
        if (d != orig_len || memcmp(tmp, buf, d) != 0)
            changed = 1;
    }

    if (changed) {
        memcpy(buf, tmp, d + 1);
    }

    return changed;
}

int fossil_ai_jellyfish_compress_chain(fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return 0;
    int changed_blocks = 0;

    size_t upper = chain->count;
    if (upper > FOSSIL_JELLYFISH_MAX_MEM) upper = FOSSIL_JELLYFISH_MAX_MEM;

    for (size_t i = 0; i < upper; ++i) {
        fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;
        if (b->attributes.compressed && b->io.compressed) continue;

        int c1 = fossil_ai_jellyfish_compress_io_field(b->io.input, sizeof(b->io.input));
        int c2 = fossil_ai_jellyfish_compress_io_field(b->io.output, sizeof(b->io.output));

        if (c1 || c2) {
            /* Recompute lengths */
            b->io.input_len  = strnlen(b->io.input,  sizeof(b->io.input));
            b->io.output_len = strnlen(b->io.output, sizeof(b->io.output));

            /* Retokenize (safe bounded) */
            b->io.input_token_count  = fossil_ai_jellyfish_tokenize(
                b->io.input, b->io.input_tokens, FOSSIL_JELLYFISH_MAX_TOKENS);
            b->io.output_token_count = fossil_ai_jellyfish_tokenize(
                b->io.output, b->io.output_tokens, FOSSIL_JELLYFISH_MAX_TOKENS);

            /* Mark compressed */
            b->attributes.compressed = 1;
            b->io.compressed = 1;

            changed_blocks++;
        }
    }

    if (changed_blocks)
        chain->updated_at = get_time_microseconds();
    return changed_blocks;
}

/* ------------------------------- Hash / Search ------------------------------ */

/**
 * Select highest-confidence valid block.
 * Complexity: O(C)
 */
const fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_best_memory(const fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return NULL;

    size_t upper = chain->count;
    if (upper > FOSSIL_JELLYFISH_MAX_MEM)
        upper = FOSSIL_JELLYFISH_MAX_MEM;

    const fossil_ai_jellyfish_block_t *best = NULL;
    float best_conf = -1.0f;

    for (size_t i = 0; i < upper; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid)
            continue;

        float c = b->attributes.confidence;
        if (c < 0.0f) c = 0.0f;
        if (c > 1.0f) c = 1.0f;

        if (c > best_conf ||
            (c == best_conf && best &&
             (b->attributes.usage_count > best->attributes.usage_count ||
              (b->attributes.usage_count == best->attributes.usage_count &&
               b->time.timestamp > best->time.timestamp)))) {
            best = b;
            best_conf = c;
        }
    }
    return best;
}

float fossil_ai_jellyfish_knowledge_coverage(const fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return 0.0f;

    const float capacity = (float)FOSSIL_JELLYFISH_MAX_MEM;
    if (capacity <= 0.0f) return 0.0f;

    uint64_t now = get_time_microseconds();
    double sum = 0.0;

    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
        if (!b->attributes.valid) continue;

        /* Base confidence clamped */
        float c = b->attributes.confidence;
        if (c < 0.0f) c = 0.0f;
        if (c > 1.0f) c = 1.0f;
        if (c == 0.0f) continue;

        /* Recency: full (1.0) if <=30s old, decays toward 0.6 */
        uint64_t ts = b->time.timestamp ? b->time.timestamp : b->time.updated_at;
        double age_s = 0.0;
        if (ts && now > ts) age_s = (double)(now - ts) / 1e6;
        double recency = 1.0;
        if (age_s > 30.0) {
            /* Exponential-ish soft decay: floor 0.6 after long time */
            double d = age_s / 300.0; /* scale ~5 min */
            recency = 0.6 + 0.4 * exp(-d);
            if (recency < 0.6) recency = 0.6;
        }

        /* Type factor */
        double type_factor = 1.0;
        switch (b->block_type) {
            case JELLY_COMMIT_VALIDATE:
            case JELLY_COMMIT_SIGNED:
            case JELLY_COMMIT_RELEASE:
                type_factor = 1.10; break;
            case JELLY_COMMIT_PATCH:
            case JELLY_COMMIT_INFER:
                type_factor = 1.00; break;
            case JELLY_COMMIT_EXPERIMENT:
            case JELLY_COMMIT_DRAFT:
            case JELLY_COMMIT_STASH:
                type_factor = 0.85; break;
            case JELLY_COMMIT_PRUNE:
            case JELLY_COMMIT_ABANDONED:
            case JELLY_COMMIT_CONFLICT:
                type_factor = 0.70; break;
            default:
                break;
        }

        /* Trust / immutability bonuses */
        double bonus = 1.0
            + (b->attributes.trusted ? 0.25 : 0.0)
            + (b->attributes.immutable ? 0.10 : 0.0);

        double w = (double)c * recency * type_factor * bonus;

        /* Cap individual contribution to avoid domination */
        if (w > 1.5) w = 1.5;

        sum += w;
    }

    /* Normalize: theoretical max ~ capacity * 1.5 -> scale to 1.0 */
    double coverage = sum / (capacity * 1.5);
    if (coverage > 1.0) coverage = 1.0;
    if (coverage < 0.0) coverage = 0.0;

    return (float)coverage;
}

int fossil_ai_jellyfish_detect_conflict(const fossil_ai_jellyfish_chain_t *chain,
                                        const char *input, const char *output) {
    if (!chain || !input || !*input)
        return -1;

    size_t upper = chain->count;
    if (upper > FOSSIL_JELLYFISH_MAX_MEM)
        upper = FOSSIL_JELLYFISH_MAX_MEM;

    int conflicts = 0;

    if (output && *output) {
        /* Compare against supplied output */
        for (size_t i = 0; i < upper; ++i) {
            const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
            if (!b->attributes.valid) continue;
            if (b->attributes.redacted || b->io.redacted) continue;
            if (strcmp(b->io.input, input) == 0) {
                if (strcmp(b->io.output, output) != 0)
                    conflicts++;
            }
        }
    } else {
        /* Derive baseline from first matching non-redacted block */
        const char *baseline = NULL;
        for (size_t i = 0; i < upper; ++i) {
            const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
            if (!b->attributes.valid) continue;
            if (b->attributes.redacted || b->io.redacted) continue;
            if (strcmp(b->io.input, input) == 0) {
                if (!baseline) {
                    baseline = b->io.output;
                } else if (strcmp(b->io.output, baseline) != 0) {
                    conflicts++;
                }
            }
        }
    }
    return conflicts;
}

const fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_find_by_hash(
    const fossil_ai_jellyfish_chain_t *chain,
    const uint8_t *hash)
{
    if (!chain || !hash) return NULL;

    size_t upper = chain->count;
    if (upper > FOSSIL_JELLYFISH_MAX_MEM)
    upper = FOSSIL_JELLYFISH_MAX_MEM;

    for (size_t i = 0; i < upper; ++i) {
    const fossil_ai_jellyfish_block_t *b = &chain->commits[i];
    if (!b->attributes.valid) continue;
    if (memcmp(b->identity.commit_hash, hash, FOSSIL_JELLYFISH_HASH_SIZE) == 0)
        return b;
    }
    return NULL;
}

fossil_ai_jellyfish_block_t *
fossil_ai_jellyfish_get(fossil_ai_jellyfish_chain_t *chain, size_t index) {
    if (!chain) return NULL;
    if (index >= FOSSIL_JELLYFISH_MAX_MEM) return NULL;
    return &chain->commits[index];
}

/* --------------------------- Block Attribute Ops --------------------------- */

void fossil_ai_jellyfish_mark_immutable(fossil_ai_jellyfish_block_t *block) {
    if (!block) return;
    if (block->attributes.immutable) return;
    block->attributes.immutable = 1;

    /* Promote trust for validated / signed / release style commits */
    if (block->block_type == JELLY_COMMIT_VALIDATE ||
        block->block_type == JELLY_COMMIT_SIGNED ||
        block->block_type == JELLY_COMMIT_RELEASE ||
        block->block_type == JELLY_COMMIT_ARCHIVE) {
        block->attributes.trusted = 1;
        if (block->attributes.confidence < 0.95f)
            block->attributes.confidence = 0.95f;
    }

    /* If freezing an ephemeral state, reclassify as ARCHIVE */
    if (block->block_type == JELLY_COMMIT_DRAFT ||
        block->block_type == JELLY_COMMIT_EXPERIMENT ||
        block->block_type == JELLY_COMMIT_STASH) {
        block->block_type = JELLY_COMMIT_ARCHIVE;
    }
}

int fossil_ai_jellyfish_redact_block(fossil_ai_jellyfish_block_t *block) {
    if (!block) return -1;
    if (!block->attributes.valid) return -2;

    char *fields[2] = { block->io.input, block->io.output };
    size_t caps[2]  = { FOSSIL_JELLYFISH_INPUT_SIZE, FOSSIL_JELLYFISH_OUTPUT_SIZE };

    int redactions = 0;

    for (int f = 0; f < 2; ++f) {
        char *buf = fields[f];
        if (!buf[0]) continue;
        size_t len = strnlen(buf, caps[f]);

        /* Pass 1: email masking */
        for (size_t i = 0; i < len; ++i) {
            if (buf[i] == '@') {
                /* Find start (back to whitespace) */
                size_t start = i;
                while (start > 0 && !isspace((unsigned char)buf[start-1])) start--;
                /* Find end */
                size_t end = i;
                while (end + 1 < len && !isspace((unsigned char)buf[end+1])) end++;
                /* Require at least one '.' after '@' to call it an email */
                int dot_after = 0;
                for (size_t k = i + 1; k <= end; ++k) if (buf[k] == '.') { dot_after = 1; break; }
                if (dot_after) {
                    for (size_t k = start; k <= end; ++k) {
                        char c = buf[k];
                        if (c == '@' || c == '.' ) continue;
                        if (!isspace((unsigned char)c))
                            buf[k] = 'x';
                    }
                    redactions++;
                    i = end;
                }
            }
        }

        /* Pass 2: UUID masking (pattern 8-4-4-4-12 with hex & hyphens) */
        for (size_t i = 0; i + 36 <= len; ++i) {
            int uuid = 1;
            const int dashes[4] = {8,13,18,23};
            for (int k = 0; k < 36 && uuid; ++k) {
                char c = buf[i+k];
                int is_dash_pos = (k==dashes[0]||k==dashes[1]||k==dashes[2]||k==dashes[3]);
                if (is_dash_pos) {
                    if (c != '-') uuid = 0;
                } else {
                    if (!isxdigit((unsigned char)c)) uuid = 0;
                }
            }
            if (uuid) {
                for (int k = 0; k < 36; ++k)
                    if (buf[i+k] != '-')
                        buf[i+k] = 'x';
                redactions++;
                i += 35;
            }
        }

        /* Pass 3: long digit sequences (>=4) */
        for (size_t i = 0; i < len; ) {
            if (isdigit((unsigned char)buf[i])) {
                size_t j = i;
                while (j < len && isdigit((unsigned char)buf[j])) j++;
                size_t run = j - i;
                if (run >= 4) {
                    for (size_t k = i; k < j; ++k)
                        buf[k] = '0';
                    redactions++;
                }
                i = j;
            } else {
                i++;
            }
        }

        /* Pass 4: 0xHEX... sequences (>=6 hex chars after 0x) */
        for (size_t i = 0; i + 2 < len; ++i) {
            if (buf[i] == '0' && (buf[i+1] == 'x' || buf[i+1] == 'X')) {
                size_t j = i + 2;
                size_t hexlen = 0;
                while (j < len && isxdigit((unsigned char)buf[j])) { j++; hexlen++; }
                if (hexlen >= 6) {
                    for (size_t k = i + 2; k < j; ++k)
                        buf[k] = 'x';
                    redactions++;
                    i = j;
                }
            }
        }

        /* Pass 5: pure hex tokens length >=16 */
        for (size_t i = 0; i < len; ) {
            if (isxdigit((unsigned char)buf[i])) {
                size_t j = i;
                while (j < len && isxdigit((unsigned char)buf[j])) j++;
                size_t run = j - i;
                if (run >= 16) {
                    for (size_t k = i; k < j; ++k)
                        buf[k] = 'x';
                    redactions++;
                }
                i = j;
            } else {
                i++;
            }
        }
    }

    if (redactions > 0) {
        /* Recompute lengths */
        block->io.input_len  = strnlen(block->io.input,  FOSSIL_JELLYFISH_INPUT_SIZE);
        block->io.output_len = strnlen(block->io.output, FOSSIL_JELLYFISH_OUTPUT_SIZE);

        /* Retokenize */
        block->io.input_token_count  = fossil_ai_jellyfish_tokenize(
            block->io.input,  block->io.input_tokens,  FOSSIL_JELLYFISH_MAX_TOKENS);
        block->io.output_token_count = fossil_ai_jellyfish_tokenize(
            block->io.output, block->io.output_tokens, FOSSIL_JELLYFISH_MAX_TOKENS);

        /* Flags */
        block->io.redacted = 1;
        block->attributes.redacted = 1;

        /* Mild confidence reduction */
        if (block->attributes.confidence > 0.0f)
            block->attributes.confidence *= 0.95f;

        /* Update timing */
        uint64_t now = get_time_microseconds();
        uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;
        block->time.delta_ms = (uint32_t)((now - prev)/1000ULL);
        block->time.updated_at = now;

        /* Re-hash content (new commit hash reflects redaction). Tree mirrors commit. */
        fossil_ai_jellyfish_hash(block->io.input, block->io.output, block->identity.commit_hash);
        memcpy(block->identity.tree_hash, block->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);
    }

    return redactions;
}

int fossil_ai_jellyfish_block_set_message(fossil_ai_jellyfish_block_t *block, const char *message) {
    if (!block || !message) return -1;

    size_t cap = sizeof(block->identity.commit_message);
    size_t newlen = strnlen(message, cap);
    if (newlen >= cap) newlen = cap - 1;

    /* Unchanged? (full buffer compare up to cap) */
    if (strncmp(block->identity.commit_message, message, cap) == 0)
        return 0;

    memcpy(block->identity.commit_message, message, newlen);
    block->identity.commit_message[newlen] = '\0';

    /* Update timing metadata */
    uint64_t now = get_time_microseconds();
    if (block->time.timestamp == 0) block->time.timestamp = now;
    uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;
    block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
    block->time.updated_at = now;

    return 1;
}

int fossil_ai_jellyfish_block_set_type(fossil_ai_jellyfish_block_t *block,
                                       fossil_ai_jellyfish_commit_type_t type)
{
    if (!block) return -1;
    if (type < JELLY_COMMIT_UNKNOWN || type > JELLY_COMMIT_FINAL) return -2;
    if (block->block_type == type) return 0;

    uint64_t now = get_time_microseconds();
    uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;

    block->block_type = type;

    /* Heuristic side-effects */
    switch (type) {
        case JELLY_COMMIT_VALIDATE:
            block->attributes.trusted = 1;
            if (block->attributes.confidence < 0.90f)
                block->attributes.confidence = 0.90f;
            block->time.validated_at = now;
            break;
        case JELLY_COMMIT_SIGNED:
            block->attributes.trusted = 1;
            if (block->attributes.confidence < 0.95f)
                block->attributes.confidence = 0.95f;
            break;
        case JELLY_COMMIT_RELEASE:
        case JELLY_COMMIT_ARCHIVE:
            if (block->attributes.confidence < 0.92f)
                block->attributes.confidence = 0.92f;
            break;
        case JELLY_COMMIT_PRUNE:
            block->attributes.valid = 0;
            block->attributes.pruned = 1;
            block->attributes.confidence = 0.0f;
            block->time.expires_at = now;
            break;
        case JELLY_COMMIT_CONFLICT:
            block->attributes.conflicted = 1;
            if (block->attributes.confidence > 0.8f)
                block->attributes.confidence *= 0.8f;
            break;
        default:
            break;
    }

    /* Merge flag consistency */
    if (block->identity.parent_count >= 2)
        block->identity.is_merge_commit = (type == JELLY_COMMIT_MERGE);

    /* Timing update */
    if (block->time.timestamp == 0) block->time.timestamp = now;
    block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
    block->time.updated_at = now;

    return 1;
}

/* --------------------------- Classification Helpers ------------------------ */

/**
 * Append tag if capacity allows.
 * Complexity: O(T_tag) (bounded).
 */
int fossil_ai_jellyfish_block_add_tag(fossil_ai_jellyfish_block_t *block, const char *tag) {
    if (!block || !tag) return -1;

    /* Trim leading/trailing whitespace */
    while (isspace((unsigned char)*tag)) tag++;
    if (*tag == '\0') return -2;

    char buf[32];
    size_t len = 0;
    /* Copy up to 31 chars, skip trailing spaces later */
    while (tag[len] && len < sizeof(buf) - 1) {
        buf[len] = tag[len];
        len++;
    }
    buf[len] = '\0';

    /* Trim trailing whitespace */
    while (len && isspace((unsigned char)buf[len - 1])) {
        buf[--len] = '\0';
    }
    if (len == 0) return -2;
    if (len >= sizeof(buf)) return -3; /* overflow safeguard */

    /* Normalize: lowercase */
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)buf[i];
        if (c >= 'A' && c <= 'Z') buf[i] = (char)(c - 'A' + 'a');
    }

    /* Reject internal whitespace (collapse not desired for tags) */
    for (size_t i = 0; i < len; ++i) {
        if (isspace((unsigned char)buf[i])) return -4;
    }

    /* Duplicate check (case-insensitive already normalized) */
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_TAGS; ++i) {
        if (block->classify.tags[i][0] == '\0') continue;
        if (strncmp(block->classify.tags[i], buf, sizeof(block->classify.tags[i])) == 0)
            return 0; /* unchanged */
    }

    /* Find insertion slot */
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_TAGS; ++i) {
        if (block->classify.tags[i][0] == '\0') {
            strncpy(block->classify.tags[i], buf, sizeof(block->classify.tags[i]) - 1);
            block->classify.tags[i][sizeof(block->classify.tags[i]) - 1] = '\0';

            /* Update timing metadata (similar to other mutators) */
            uint64_t now = get_time_microseconds();
            if (block->time.timestamp == 0) block->time.timestamp = now;
            uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;
            block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
            block->time.updated_at = now;
            return 1; /* added */
        }
    }

    return -5; /* no capacity */
}

int fossil_ai_jellyfish_block_set_reason(fossil_ai_jellyfish_block_t *block, const char *reason) {
    if (!block || !reason) return -1;

    /* Trim leading whitespace */
    while (*reason && isspace((unsigned char)*reason)) reason++;
    if (!*reason) return -2; /* empty after trim */

    /* Copy with collapsing internal whitespace runs to single space, trimming trailing */
    char buf[128];
    size_t cap = sizeof(buf);
    size_t w = 0;
    int in_space = 0;
    for (size_t i = 0; reason[i] && w + 1 < cap; ++i) {
        unsigned char c = (unsigned char)reason[i];
        if (isspace(c)) {
            in_space = 1;
            continue;
        }
        if (in_space && w > 0) {
            buf[w++] = ' ';
        }
        in_space = 0;
        /* Filter control chars */
        if (c < 32 || c == 127) continue;
        buf[w++] = (char)c;
    }
    if (w > 0 && buf[w - 1] == ' ')
        w--;
    buf[w] = '\0';
    if (w == 0) return -2;

    /* Unchanged? */
    if (strncmp(block->classify.classification_reason, buf, sizeof(block->classify.classification_reason)) == 0)
        return 0;

    memcpy(block->classify.classification_reason, buf, w + 1);

    /* Update timing metadata similar to other mutators */
    uint64_t now = get_time_microseconds();
    if (block->time.timestamp == 0) block->time.timestamp = now;
    uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;
    block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
    block->time.updated_at = now;

    return 1;
}

int fossil_ai_jellyfish_block_set_similarity(fossil_ai_jellyfish_block_t *block, float similarity) {
    if (!block) return -1;

    /* Normalize input */
    if (similarity != similarity) similarity = 0.0f; /* NaN -> 0 */
    if (similarity < 0.0f) similarity = 0.0f;
    if (similarity > 1.0f) similarity = 1.0f;

    float old = block->classify.similarity_score;
    float diff = old - similarity;
    if (diff < 0.0f) diff = -diff;
    if (diff < 0.0001f)
        return 0; /* unchanged */

    block->classify.similarity_score = similarity;

    /* Heuristic flags */
    if (similarity < 0.20f) {
        block->classify.is_hallucinated = 1;
        if (!block->attributes.immutable && block->attributes.confidence > 0.0f) {
            block->attributes.confidence *= 0.90f;
            if (block->attributes.confidence < 0.0f) block->attributes.confidence = 0.0f;
        }
    } else if (similarity > 0.30f && block->classify.is_hallucinated) {
        block->classify.is_hallucinated = 0;
    }

    if (similarity < 0.05f)
        block->classify.is_contradicted = 1;
    else if (similarity > 0.15f && block->classify.is_contradicted)
        block->classify.is_contradicted = 0;

    /* Timing update */
    uint64_t now = get_time_microseconds();
    if (block->time.timestamp == 0) block->time.timestamp = now;
    uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;
    block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
    block->time.updated_at = now;

    return 1; /* modified */
}

int fossil_ai_jellyfish_block_link_forward(fossil_ai_jellyfish_block_t *block, uint32_t target_index) {
    if (!block) return -1;
    if (target_index >= (uint32_t)FOSSIL_JELLYFISH_MAX_MEM) return -2;
    if (block->identity.commit_index == target_index) return -4;

    /* Duplicate check */
    for (size_t i = 0; i < block->classify.forward_ref_count; ++i) {
        if (block->classify.forward_refs[i] == target_index)
            return 0; /* already linked */
    }

    if (block->classify.forward_ref_count >= FOSSIL_JELLYFISH_MAX_LINKS)
        return -3;

    block->classify.forward_refs[block->classify.forward_ref_count++] = target_index;

    /* Heuristic: increase reasoning depth on new forward derivation */
    if (block->classify.reasoning_depth < 0xFFFF)
        block->classify.reasoning_depth++;

    /* Timing update */
    uint64_t now = get_time_microseconds();
    uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;
    if (block->time.timestamp == 0) block->time.timestamp = now;
    block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
    block->time.updated_at = now;

    return 1;
}

int fossil_ai_jellyfish_block_link_cross(fossil_ai_jellyfish_block_t *block, uint32_t target_index) {
    if (!block) return -1;
    if (target_index >= (uint32_t)FOSSIL_JELLYFISH_MAX_MEM) return -2;
    if (block->identity.commit_index == target_index) return -4;

    for (size_t i = 0; i < block->classify.cross_ref_count; ++i) {
        if (block->classify.cross_refs[i] == target_index)
            return 0;
    }

    if (block->classify.cross_ref_count >= FOSSIL_JELLYFISH_MAX_LINKS)
        return -3;

    block->classify.cross_refs[block->classify.cross_ref_count++] = target_index;

    /* Timing update */
    uint64_t now = get_time_microseconds();
    uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;
    if (block->time.timestamp == 0) block->time.timestamp = now;
    block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
    block->time.updated_at = now;

    return 1;
}

/* ------------------------------ Git-Chain Ops ------------------------------ */

fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_add_commit(
    fossil_ai_jellyfish_chain_t *chain,
    const char *input,
    const char *output,
    fossil_ai_jellyfish_commit_type_t type,
    const uint8_t parent_hashes[][FOSSIL_JELLYFISH_HASH_SIZE],
    size_t parent_count,
    const char *message)
{
    if (!chain || !input || !output) return NULL;

    /* Locate slot: append or first invalid */
    size_t index = SIZE_MAX;
    if (chain->count < FOSSIL_JELLYFISH_MAX_MEM) {
        index = chain->count;
    } else {
        for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
            if (!chain->commits[i].attributes.valid) {
                index = i;
                break;
            }
        }
    }
    if (index == SIZE_MAX) return NULL;

    fossil_ai_jellyfish_block_t *b = &chain->commits[index];
    memset(b, 0, sizeof(*b));

    /* IO */
    strncpy(b->io.input,  input,  FOSSIL_JELLYFISH_INPUT_SIZE  - 1);
    strncpy(b->io.output, output, FOSSIL_JELLYFISH_OUTPUT_SIZE - 1);
    b->io.input_len  = strnlen(b->io.input,  FOSSIL_JELLYFISH_INPUT_SIZE);
    b->io.output_len = strnlen(b->io.output, FOSSIL_JELLYFISH_OUTPUT_SIZE);

    b->io.input_token_count  = fossil_ai_jellyfish_tokenize(
        b->io.input,  b->io.input_tokens,  FOSSIL_JELLYFISH_MAX_TOKENS);
    b->io.output_token_count = fossil_ai_jellyfish_tokenize(
        b->io.output, b->io.output_tokens, FOSSIL_JELLYFISH_MAX_TOKENS);

    /* Initial hash from IO */
    fossil_ai_jellyfish_hash(b->io.input, b->io.output, b->identity.commit_hash);

    /* Parent handling */
    if (parent_count > 4) parent_count = 4;
    b->identity.parent_count = parent_count;
    for (size_t p = 0; p < parent_count; ++p) {
        memcpy(b->identity.parent_hashes[p], parent_hashes[p], FOSSIL_JELLYFISH_HASH_SIZE);
        /* Mix parent hash into commit hash (simple XOR diffusion) */
        for (size_t k = 0; k < FOSSIL_JELLYFISH_HASH_SIZE; ++k) {
            b->identity.commit_hash[k] ^= (uint8_t)(parent_hashes[p][k] + (uint8_t)(type * (p + 1)));
        }
    }

    /* Mix type discriminator */
    for (size_t k = 0; k < FOSSIL_JELLYFISH_HASH_SIZE; ++k)
        b->identity.commit_hash[k] ^= (uint8_t)((type * 31u) + (uint8_t)k);

    memcpy(b->identity.tree_hash, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);

    /* Identity */
    b->identity.commit_index = (uint32_t)index;
    b->identity.branch_id = 0;
    b->block_type = type;
    b->identity.is_merge_commit = (parent_count >= 2) ? 1 : 0;
    b->identity.detached = (type == JELLY_COMMIT_DETACHED);
    if (message) {
        strncpy(b->identity.commit_message, message, sizeof(b->identity.commit_message) - 1);
    }

    /* Author / committer from repo_id */
    memcpy(b->identity.author_id,   chain->repo_id, FOSSIL_DEVICE_ID_SIZE);
    memcpy(b->identity.committer_id, chain->repo_id, FOSSIL_DEVICE_ID_SIZE);

    /* FSON roots */
    fossil_ai_jellyfish_fson_init(&b->classify.semantic_meta);
    fossil_ai_jellyfish_fson_make_object(&b->classify.semantic_meta);
    fossil_ai_jellyfish_fson_init(&b->io.io_meta);
    fossil_ai_jellyfish_fson_make_object(&b->io.io_meta);
    fossil_ai_jellyfish_fson_init(&b->fson.root);
    fossil_ai_jellyfish_fson_make_object(&b->fson.root);
    fossil_ai_jellyfish_fson_init(&b->audit_meta);
    fossil_ai_jellyfish_fson_make_object(&b->audit_meta);

    /* Attributes & heuristics */
    b->attributes.valid = 1;
    b->attributes.usage_count = 0;
    switch (type) {
        case JELLY_COMMIT_VALIDATE: b->attributes.confidence = 0.90f; b->attributes.trusted = 1; break;
        case JELLY_COMMIT_SIGNED:   b->attributes.confidence = 0.95f; b->attributes.trusted = 1; break;
        case JELLY_COMMIT_RELEASE:  b->attributes.confidence = 0.92f; break;
        case JELLY_COMMIT_EXPERIMENT: b->attributes.confidence = 0.55f; break;
        case JELLY_COMMIT_DRAFT:    b->attributes.confidence = 0.45f; break;
        case JELLY_COMMIT_PATCH:    b->attributes.confidence = 0.80f; break;
        case JELLY_COMMIT_INFER:    b->attributes.confidence = 0.75f; break;
        default:                    b->attributes.confidence = 0.70f; break;
    }

    uint64_t now = get_time_microseconds();
    b->time.timestamp = now;
    b->time.updated_at = now;

    /* Branch head update (default branch 0) */
    if (chain->branch_count > 0) {
        memcpy(chain->branches[0].head_hash, b->identity.commit_hash, FOSSIL_JELLYFISH_HASH_SIZE);
    }

    /* Chain bookkeeping */
    if (index == chain->count && chain->count < FOSSIL_JELLYFISH_MAX_MEM)
        chain->count++;
    chain->updated_at = now;

    return b;
}

int fossil_ai_jellyfish_commit_set_parents(fossil_ai_jellyfish_block_t *block,
                                           const uint8_t parent_hashes[][FOSSIL_JELLYFISH_HASH_SIZE],
                                           size_t parent_count)
{
    if (!block) return -1;
    if (parent_count > 4) return -2;
    if (parent_count > 0 && !parent_hashes) return -3;

    /* Fast unchanged check */
    int identical = 1;
    if (parent_count != block->identity.parent_count) {
        identical = 0;
    } else {
        for (size_t p = 0; p < parent_count && identical; ++p) {
            if (memcmp(block->identity.parent_hashes[p],
                       parent_hashes[p],
                       FOSSIL_JELLYFISH_HASH_SIZE) != 0) {
                identical = 0;
            }
        }
    }
    if (identical) return 0;

    /* Validate inputs: no self-parent, no duplicates */
    for (size_t p = 0; p < parent_count; ++p) {
        if (memcmp(parent_hashes[p],
                   block->identity.commit_hash,
                   FOSSIL_JELLYFISH_HASH_SIZE) == 0)
            return -4;
        for (size_t q = p + 1; q < parent_count; ++q) {
            if (memcmp(parent_hashes[p],
                       parent_hashes[q],
                       FOSSIL_JELLYFISH_HASH_SIZE) == 0)
                return -5;
        }
    }

    /* Copy parents */
    for (size_t p = 0; p < parent_count; ++p) {
        memcpy(block->identity.parent_hashes[p],
               parent_hashes[p],
               FOSSIL_JELLYFISH_HASH_SIZE);
    }
    /* Zero any leftover slots from previous larger parent_count */
    for (size_t p = parent_count; p < 4; ++p) {
        memset(block->identity.parent_hashes[p], 0, FOSSIL_JELLYFISH_HASH_SIZE);
    }
    block->identity.parent_count = parent_count;
    block->identity.is_merge_commit = (parent_count >= 2) ? 1 : 0;
    if (block->block_type == JELLY_COMMIT_MERGE && parent_count < 2) {
        /* Demote merge flag inconsistency */
        block->block_type = JELLY_COMMIT_PATCH;
    }
    if (parent_count >= 2 && block->block_type == JELLY_COMMIT_INFER) {
        /* Heuristic: upgrade to MERGE if now multi-parent */
        block->block_type = JELLY_COMMIT_MERGE;
        block->identity.is_merge_commit = 1;
    }

    /* Recompute base hash from IO */
    fossil_ai_jellyfish_hash(block->io.input,
                             block->io.output,
                             block->identity.commit_hash);

    /* Mix parents and type exactly like add_commit() */
    for (size_t p = 0; p < parent_count; ++p) {
        for (size_t k = 0; k < FOSSIL_JELLYFISH_HASH_SIZE; ++k) {
            block->identity.commit_hash[k] ^=
                (uint8_t)(block->identity.parent_hashes[p][k] +
                          (uint8_t)(block->block_type * (p + 1)));
        }
    }
    for (size_t k = 0; k < FOSSIL_JELLYFISH_HASH_SIZE; ++k) {
        block->identity.commit_hash[k] ^=
            (uint8_t)((block->block_type * 31u) + (uint8_t)k);
    }
    memcpy(block->identity.tree_hash,
           block->identity.commit_hash,
           FOSSIL_JELLYFISH_HASH_SIZE);

    /* Update timing */
    uint64_t now = get_time_microseconds();
    if (block->time.timestamp == 0) block->time.timestamp = now;
    uint64_t prev = block->time.updated_at ?
                    block->time.updated_at : block->time.timestamp;
    block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
    block->time.updated_at = now;

    return 1;
}

const char *fossil_ai_jellyfish_commit_type_name(fossil_ai_jellyfish_commit_type_t type) {
    switch (type) {
        case JELLY_COMMIT_UNKNOWN:      return "UNKNOWN";
        case JELLY_COMMIT_INIT:         return "INIT";
        case JELLY_COMMIT_OBSERVE:      return "OBSERVE";
        case JELLY_COMMIT_INFER:        return "INFER";
        case JELLY_COMMIT_VALIDATE:     return "VALIDATE";
        case JELLY_COMMIT_PATCH:        return "PATCH";

        case JELLY_COMMIT_BRANCH:       return "BRANCH";
        case JELLY_COMMIT_MERGE:        return "MERGE";
        case JELLY_COMMIT_REBASE:       return "REBASE";
        case JELLY_COMMIT_CHERRY_PICK:  return "CHERRY_PICK";
        case JELLY_COMMIT_FORK:         return "FORK";

        case JELLY_COMMIT_TAG:          return "TAG";
        case JELLY_COMMIT_RELEASE:      return "RELEASE";
        case JELLY_COMMIT_ARCHIVE:      return "ARCHIVE";
        case JELLY_COMMIT_SNAPSHOT:     return "SNAPSHOT";

        case JELLY_COMMIT_EXPERIMENT:   return "EXPERIMENT";
        case JELLY_COMMIT_STASH:        return "STASH";
        case JELLY_COMMIT_DRAFT:        return "DRAFT";
        case JELLY_COMMIT_REVERT:       return "REVERT";
        case JELLY_COMMIT_ROLLBACK:     return "ROLLBACK";

        case JELLY_COMMIT_SYNC:         return "SYNC";
        case JELLY_COMMIT_MIRROR:       return "MIRROR";
        case JELLY_COMMIT_IMPORT:       return "IMPORT";
        case JELLY_COMMIT_EXPORT:       return "EXPORT";
        case JELLY_COMMIT_SIGNED:       return "SIGNED";
        case JELLY_COMMIT_REVIEW:       return "REVIEW";

        case JELLY_COMMIT_DETACHED:     return "DETACHED";
        case JELLY_COMMIT_ABANDONED:    return "ABANDONED";
        case JELLY_COMMIT_CONFLICT:     return "CONFLICT";
        case JELLY_COMMIT_PRUNE:        return "PRUNE";
        case JELLY_COMMIT_FINAL:        return "FINAL";
        default:                        return "UNKNOWN";
    }
}

/* Branch management */

int fossil_ai_jellyfish_branch_create(fossil_ai_jellyfish_chain_t *chain, const char *name) {
    if (!chain || !name) return -1;

    /* Trim leading/trailing whitespace */
    while (*name && isspace((unsigned char)*name)) name++;
    size_t len = strnlen(name, 64);
    while (len && isspace((unsigned char)name[len - 1])) len--;

    if (len == 0 || len >= sizeof(chain->branches[0].name)) return -3;

    /* Validate characters (allow A-Z a-z 0-9 _ - .) */
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!(isalnum(c) || c == '_' || c == '-' || c == '.'))
            return -3;
    }

    /* Duplicate check */
    for (size_t i = 0; i < chain->branch_count; ++i) {
        if (strncmp(chain->branches[i].name, name, sizeof(chain->branches[i].name)) == 0) {
            return (int)i; /* existing branch */
        }
    }

    if (chain->branch_count >= FOSSIL_JELLYFISH_MAX_BRANCHES) return -2;

    size_t idx = chain->branch_count++;

    /* Initialize new branch record */
    memset(&chain->branches[idx], 0, sizeof(chain->branches[idx]));
    memcpy(chain->branches[idx].name, name, len);
    chain->branches[idx].name[len] = '\0';

    /* Inherit head from active (default) branch if present, else zero */
    int active = -1;
    for (size_t i = 0; i < chain->branch_count - 1; ++i) {
        if (strncmp(chain->branches[i].name, chain->default_branch, sizeof(chain->branches[i].name)) == 0) {
            active = (int)i;
            break;
        }
    }
    if (active >= 0) {
        memcpy(chain->branches[idx].head_hash,
               chain->branches[active].head_hash,
               FOSSIL_JELLYFISH_HASH_SIZE);
    } else if (chain->branch_count > 1) {
        /* Fallback: copy from branch 0 */
        memcpy(chain->branches[idx].head_hash,
               chain->branches[0].head_hash,
               FOSSIL_JELLYFISH_HASH_SIZE);
    } /* else (first branch) head already zeroed */

    /* Initialize branch_meta FSON object */
    fossil_ai_jellyfish_fson_init(&chain->branches[idx].branch_meta);
    fossil_ai_jellyfish_fson_make_object(&chain->branches[idx].branch_meta);

    chain->updated_at = get_time_microseconds();
    return (int)idx;
}

int fossil_ai_jellyfish_branch_checkout(fossil_ai_jellyfish_chain_t *chain, const char *name) {
    if (!chain || !name) return -1;

    /* Trim leading / trailing whitespace (mirror validation style of _branch_create) */
    while (*name && isspace((unsigned char)*name)) name++;
    size_t len = strnlen(name, sizeof(chain->branches[0].name));
    while (len && isspace((unsigned char)name[len - 1])) len--;

    if (len == 0 || len >= sizeof(chain->branches[0].name))
        return -3;

    /* Find existing branch */
    int found = -2;
    for (size_t i = 0; i < chain->branch_count; ++i) {
        if (strncmp(chain->branches[i].name, name, sizeof(chain->branches[i].name)) == 0) {
            found = (int)i;
            break;
        }
    }
    if (found < 0) return found;

    /* Update active (default) branch name if different */
    if (strncmp(chain->default_branch, chain->branches[found].name,
                sizeof(chain->default_branch)) != 0) {
        strncpy(chain->default_branch, chain->branches[found].name,
                sizeof(chain->default_branch) - 1);
        chain->default_branch[sizeof(chain->default_branch) - 1] = '\0';
        chain->updated_at = get_time_microseconds();
    }

    return found;
}

int fossil_ai_jellyfish_branch_find(const fossil_ai_jellyfish_chain_t *chain, const char *name) {
    if (!chain || !name) return -1;

    /* Trim leading / trailing whitespace (mirror create/checkout) */
    while (*name && isspace((unsigned char)*name)) name++;
    size_t len = strnlen(name, sizeof(chain->branches[0].name));
    while (len && isspace((unsigned char)name[len - 1])) len--;

    if (len == 0 || len >= sizeof(chain->branches[0].name))
        return -3; /* invalid name */

    for (size_t i = 0; i < chain->branch_count; ++i) {
        if (strncmp(chain->branches[i].name, name, sizeof(chain->branches[i].name)) == 0)
            return (int)i;
    }
    return -2; /* not found */
}

const char *fossil_ai_jellyfish_branch_active(const fossil_ai_jellyfish_chain_t *chain) {
    if (!chain) return NULL;
    if (chain->default_branch[0] != '\0')
        return chain->default_branch;
    if (chain->branch_count > 0)
        return chain->branches[0].name;
    return NULL;
}

int fossil_ai_jellyfish_branch_head_update(fossil_ai_jellyfish_chain_t *chain, const uint8_t *new_head_hash) {
    if (!chain || !new_head_hash)
        return -1;

    int active = -1;
    if (chain->default_branch[0]) {
        for (size_t i = 0; i < chain->branch_count; ++i) {
            if (strncmp(chain->branches[i].name, chain->default_branch, sizeof(chain->branches[i].name)) == 0) {
                active = (int)i;
                break;
            }
        }
    }
    if (active < 0 && chain->branch_count > 0)
        active = 0;

    if (active < 0 || active >= (int)chain->branch_count)
        return -2;

    memcpy(chain->branches[active].head_hash, new_head_hash, FOSSIL_JELLYFISH_HASH_SIZE);
    chain->updated_at = get_time_microseconds();
    return active;
}

/* Merge / rebase / cherry-pick */

int fossil_ai_jellyfish_merge(fossil_ai_jellyfish_chain_t *chain,
                           const char *source_branch,
                           const char *target_branch,
                           const char *message)
{
    if (!chain || !source_branch || !target_branch) return -1;

    int sidx = fossil_ai_jellyfish_branch_find(chain, source_branch);
    if (sidx < 0) return -2;
    int tidx = fossil_ai_jellyfish_branch_find(chain, target_branch);
    if (tidx < 0) return -3;
    if (sidx == tidx) return -4;

    const uint8_t *src_head = chain->branches[sidx].head_hash;
    const uint8_t *tgt_head = chain->branches[tidx].head_hash;

    /* Detect empty heads (all zero) */
    int src_empty = 1, tgt_empty = 1;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_HASH_SIZE; ++i) {
        if (src_head[i]) { src_empty = 0; }
        if (tgt_head[i]) { tgt_empty = 0; }
    }
    if (src_empty) return -5;
    if (tgt_empty) return -6;

    const fossil_ai_jellyfish_block_t *src_block =
        fossil_ai_jellyfish_find_by_hash(chain, src_head);
    const fossil_ai_jellyfish_block_t *tgt_block =
        fossil_ai_jellyfish_find_by_hash(chain, tgt_head);

    if (!src_block || !tgt_block) {
        /* Heads became invalid — treat as empty */
        if (!src_block) return -5;
        if (!tgt_block) return -6;
    }

    /* Build synthetic merge input/output (bounded) */
    char merge_input[FOSSIL_JELLYFISH_INPUT_SIZE];
    char merge_output[FOSSIL_JELLYFISH_OUTPUT_SIZE];

    snprintf(merge_input, sizeof(merge_input),
             "merge:%s->%s", source_branch, target_branch);

    /* Prefer target output as resulting state */
    if (tgt_block && tgt_block->io.output[0]) {
        strncpy(merge_output, tgt_block->io.output, sizeof(merge_output) - 1);
        merge_output[sizeof(merge_output) - 1] = '\0';
    } else {
        strncpy(merge_output, src_block && src_block->io.output[0] ?
                src_block->io.output : "merged", sizeof(merge_output) - 1);
        merge_output[sizeof(merge_output) - 1] = '\0';
    }

    /* Parent order: target first, then source (like git merge) */
    uint8_t parents[2][FOSSIL_JELLYFISH_HASH_SIZE];
    memcpy(parents[0], tgt_head, FOSSIL_JELLYFISH_HASH_SIZE);
    memcpy(parents[1], src_head, FOSSIL_JELLYFISH_HASH_SIZE);

    char msg_buf[256];
    const char *final_msg = message;
    if (!final_msg || !final_msg[0]) {
        snprintf(msg_buf, sizeof(msg_buf),
                 "merge %s into %s", source_branch, target_branch);
        final_msg = msg_buf;
    }

    fossil_ai_jellyfish_block_t *merge_commit =
        fossil_ai_jellyfish_add_commit(chain,
                                       merge_input,
                                       merge_output,
                                       JELLY_COMMIT_MERGE,
                                       parents,
                                       2,
                                       final_msg);
    if (!merge_commit) return -7;

    /* Conflict heuristic: same input different outputs */
    if (src_block && tgt_block &&
        strcmp(src_block->io.input, tgt_block->io.input) == 0 &&
        strcmp(src_block->io.output, tgt_block->io.output) != 0) {
        merge_commit->attributes.conflicted = 1;
        /* Mild confidence penalty */
        if (merge_commit->attributes.confidence > 0.1f)
            merge_commit->attributes.confidence *= 0.9f;

        /* Append note if room */
        size_t ml = strnlen(merge_commit->identity.commit_message,
                            sizeof(merge_commit->identity.commit_message));
        const char *note = " (conflict)";
        size_t note_len = strlen(note);
        if (ml + note_len + 1 < sizeof(merge_commit->identity.commit_message)) {
            memcpy(merge_commit->identity.commit_message + ml, note, note_len + 1);
        }
    }

    /* Ensure branch head updated for target branch */
    memcpy(chain->branches[tidx].head_hash,
           merge_commit->identity.commit_hash,
           FOSSIL_JELLYFISH_HASH_SIZE);

    /* If target is active branch, update default_branch head implicitly (branch 0 heuristic) */
    if (strncmp(chain->default_branch,
                chain->branches[tidx].name,
                sizeof(chain->default_branch)) == 0) {
        /* Nothing extra needed: consumer functions treat default_branch by name */
    }

    return (int)merge_commit->identity.commit_index;
}

int fossil_ai_jellyfish_rebase(fossil_ai_jellyfish_chain_t *chain,
                               const char *branch,
                               const char *onto_branch)
{
    if (!chain || !branch || !onto_branch) return -1;

    /* Locate branches */
    int b_src  = fossil_ai_jellyfish_branch_find(chain, branch);
    if (b_src < 0) return -2;
    int b_onto = fossil_ai_jellyfish_branch_find(chain, onto_branch);
    if (b_onto < 0) return -3;
    if (b_src == b_onto) return -4;

    const uint8_t *src_head  = chain->branches[b_src].head_hash;
    const uint8_t *onto_head = chain->branches[b_onto].head_hash;

    /* Check empty heads (all zeros) */
    int src_empty = 1, onto_empty = 1;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_HASH_SIZE; ++i) {
        if (src_head[i])  src_empty  = 0;
        if (onto_head[i]) onto_empty = 0;
    }
    if (src_empty)  return -5;
    if (onto_empty) return -6;

    const fossil_ai_jellyfish_block_t *src_block =
        fossil_ai_jellyfish_find_by_hash(chain, src_head);
    const fossil_ai_jellyfish_block_t *onto_block =
        fossil_ai_jellyfish_find_by_hash(chain, onto_head);

    if (!src_block) return -5;
    if (!onto_block) return -6;

    /* Build rebase commit IO (reuse original source head content) */
    const char *input  = src_block->io.input[0]  ? src_block->io.input  : "rebase";
    const char *output = src_block->io.output[0] ? src_block->io.output : "rebased";

    /* Single parent = onto head (classic linear rebase replay) */
    uint8_t parent[1][FOSSIL_JELLYFISH_HASH_SIZE];
    memcpy(parent[0], onto_head, FOSSIL_JELLYFISH_HASH_SIZE);

    char msg[256];
    snprintf(msg, sizeof(msg), "rebase %s onto %s (src:%s)",
             chain->branches[b_src].name,
             chain->branches[b_onto].name,
             src_block->identity.commit_message[0] ?
                 src_block->identity.commit_message : "head");

    fossil_ai_jellyfish_block_t *rebased =
        fossil_ai_jellyfish_add_commit(chain,
                                       input,
                                       output,
                                       JELLY_COMMIT_REBASE,
                                       parent,
                                       1,
                                       msg);
    if (!rebased) return -7;

    /* Update source branch head to new rebased commit */
    memcpy(chain->branches[b_src].head_hash,
           rebased->identity.commit_hash,
           FOSSIL_JELLYFISH_HASH_SIZE);

    /* If rebasing active branch name, default_branch remains same (head already updated) */

    return (int)rebased->identity.commit_index;
}

int fossil_ai_jellyfish_cherry_pick(fossil_ai_jellyfish_chain_t *chain, const uint8_t *commit_hash) {
    if (!chain || !commit_hash) return -1;

    /* Locate source commit */
    const fossil_ai_jellyfish_block_t *src =
        fossil_ai_jellyfish_find_by_hash(chain, commit_hash);
    if (!src || !src->attributes.valid) return -2;

    /* Determine active branch index */
    int active = -1;
    if (chain->default_branch[0]) {
        for (size_t i = 0; i < chain->branch_count; ++i) {
            if (strncmp(chain->branches[i].name,
                        chain->default_branch,
                        sizeof(chain->branches[i].name)) == 0) {
                active = (int)i;
                break;
            }
        }
    }
    if (active < 0 && chain->branch_count > 0)
        active = 0;
    if (active < 0) return -3; /* no branch available */

    /* Parent = current active head (if any) */
    uint8_t parents[1][FOSSIL_JELLYFISH_HASH_SIZE];
    size_t parent_count = 0;
    int head_nonzero = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_HASH_SIZE; ++i)
        if (chain->branches[active].head_hash[i]) { head_nonzero = 1; break; }
    if (head_nonzero) {
        memcpy(parents[0], chain->branches[active].head_hash, FOSSIL_JELLYFISH_HASH_SIZE);
        parent_count = 1;
    }

    /* Build commit message */
    char msg[256];
    const char *orig_msg = src->identity.commit_message[0] ? src->identity.commit_message : "(no message)";
    snprintf(msg, sizeof(msg), "cherry-pick %u: %s",
             src->identity.commit_index, orig_msg);

    /* Add new commit */
    fossil_ai_jellyfish_block_t *newb =
        fossil_ai_jellyfish_add_commit(chain,
                                       src->io.input,
                                       src->io.output,
                                       JELLY_COMMIT_CHERRY_PICK,
                                       parent_count ? parents : NULL,
                                       parent_count,
                                       msg);
    if (!newb) return -4;

    /* Optionally inherit higher confidence */
    if (src->attributes.confidence > newb->attributes.confidence)
        newb->attributes.confidence = src->attributes.confidence;

    /* Update the active branch head explicitly if not branch 0 */
    if (active >= 0) {
        memcpy(chain->branches[active].head_hash,
               newb->identity.commit_hash,
               FOSSIL_JELLYFISH_HASH_SIZE);
    }

    return (int)newb->identity.commit_index;
}

/* Tagging */

/**
 * Add tag to block (delegates to classification tags).
 * Complexity: O(1)
 */
int fossil_ai_jellyfish_tag_block(fossil_ai_jellyfish_block_t *block, const char *tag) {
    return fossil_ai_jellyfish_block_add_tag(block, tag);
}

/* ------------------------------ FSON Utilities ----------------------------- */

/**
 * Initialize FSON value to NULL type.
 * Complexity: O(1)
 */
void fossil_ai_jellyfish_fson_init(fossil_ai_jellyfish_fson_value_t *v) {
    if (!v) return;
    memset(v, 0, sizeof(*v));
    v->type = JELLYFISH_FSON_TYPE_NULL;
    /* All union fields zeroed; pointers (cstr, enum_val.symbol/allowed, children) now NULL */
}

void fossil_ai_jellyfish_fson_reset(fossil_ai_jellyfish_fson_value_t *v) {
    if (!v) return;

    switch (v->type) {
        case JELLYFISH_FSON_TYPE_CSTR:
            if (v->u.cstr) {
                free(v->u.cstr);
                v->u.cstr = NULL;
            }
            break;
        case JELLYFISH_FSON_TYPE_ENUM:
            if (v->u.enum_val.symbol) {
                free(v->u.enum_val.symbol);
                v->u.enum_val.symbol = NULL;
            }
            /* enum_val.allowed is not owned (const) */
            v->u.enum_val.allowed = NULL;
            v->u.enum_val.allowed_count = 0;
            break;
        case JELLYFISH_FSON_TYPE_ARRAY: {
            size_t n = v->u.array.count;
            for (size_t i = 0; i < n; ++i) {
                fossil_ai_jellyfish_fson_value_t *child = v->u.array.items[i];
                if (child) {
                    /* Recursive reset + free */
                    fossil_ai_jellyfish_fson_reset(child);
                    free(child);
                    v->u.array.items[i] = NULL;
                }
            }
            v->u.array.count = 0;
            break;
        }
        case JELLYFISH_FSON_TYPE_OBJECT: {
            size_t n = v->u.object.count;
            for (size_t i = 0; i < n; ++i) {
                fossil_ai_jellyfish_fson_value_t *child = v->u.object.values[i];
                if (child) {
                    fossil_ai_jellyfish_fson_reset(child);
                    free(child);
                    v->u.object.values[i] = NULL;
                }
                v->u.object.keys[i][0] = '\0';
            }
            v->u.object.count = 0;
            break;
        }
        default:
            /* Other scalar types have no dynamic ownership */
            break;
    }

    /* Final clear */
    memset(v, 0, sizeof(*v));
    v->type = JELLYFISH_FSON_TYPE_NULL;
}

/**
 * Set C-string (duplicates / owns).
 * Complexity: O(len)
 * Returns:
 *   1 -> value set / changed
 *   0 -> unchanged (same string already stored)
 *  -1 -> invalid args
 *  -2 -> allocation failure
 */
int fossil_ai_jellyfish_fson_set_cstr(fossil_ai_jellyfish_fson_value_t *v, const char *s) {
    if (!v || !s) return -1;

    /* Fast unchanged check if already CSTR */
    if (v->type == JELLYFISH_FSON_TYPE_CSTR && v->u.cstr) {
        if (strcmp(v->u.cstr, s) == 0)
            return 0; /* unchanged */
        /* Different -> replace */
        free(v->u.cstr);
        v->u.cstr = NULL;
    } else {
        /* Clear any previous content if it held owned data */
        if (v->type != JELLYFISH_FSON_TYPE_NULL) {
            fossil_ai_jellyfish_fson_reset(v);
        }
    }

    size_t len = strlen(s);
    char *dup = (char *)malloc(len + 1);
    if (!dup) {
        v->type = JELLYFISH_FSON_TYPE_NULL;
        return -2;
    }
    memcpy(dup, s, len + 1);

    v->type = JELLYFISH_FSON_TYPE_CSTR;
    v->u.cstr = dup;
    return 1;
}

int fossil_ai_jellyfish_fson_set_i64(fossil_ai_jellyfish_fson_value_t *v, int64_t val) {
    if (!v) return -1;

    if (v->type == JELLYFISH_FSON_TYPE_I64 && v->u.i64 == val)
        return 0; /* unchanged */

    /* Free owned resources if switching from owning/dynamic type */
    if (v->type == JELLYFISH_FSON_TYPE_CSTR ||
        v->type == JELLYFISH_FSON_TYPE_ENUM ||
        v->type == JELLYFISH_FSON_TYPE_ARRAY ||
        v->type == JELLYFISH_FSON_TYPE_OBJECT) {
        fossil_ai_jellyfish_fson_reset(v); /* sets type=NULL */
    }

    v->type = JELLYFISH_FSON_TYPE_I64;
    v->u.i64 = val;
    return 1;
}

int fossil_ai_jellyfish_fson_set_f64(fossil_ai_jellyfish_fson_value_t *v, double val) {
    if (!v) return -1;
    if (val != val) val = 0.0; /* NaN -> 0 */
    if (v->type == JELLYFISH_FSON_TYPE_F64 && v->u.f64 == val)
        return 0;

    /* Free owned resources if switching from a dynamic/owned type */
    if (v->type == JELLYFISH_FSON_TYPE_CSTR ||
        v->type == JELLYFISH_FSON_TYPE_ENUM ||
        v->type == JELLYFISH_FSON_TYPE_ARRAY ||
        v->type == JELLYFISH_FSON_TYPE_OBJECT) {
        fossil_ai_jellyfish_fson_reset(v); /* sets to NULL */
    }

    v->type = JELLYFISH_FSON_TYPE_F64;
    v->u.f64 = val;
    return 1;
}

int fossil_ai_jellyfish_fson_set_bool(fossil_ai_jellyfish_fson_value_t *v, int val) {
    if (!v) return -1;
    val = val ? 1 : 0;
    if (v->type == JELLYFISH_FSON_TYPE_BOOL && v->u.boolean == val)
        return 0;

    if (v->type == JELLYFISH_FSON_TYPE_CSTR ||
        v->type == JELLYFISH_FSON_TYPE_ENUM ||
        v->type == JELLYFISH_FSON_TYPE_ARRAY ||
        v->type == JELLYFISH_FSON_TYPE_OBJECT) {
        fossil_ai_jellyfish_fson_reset(v);
    }

    v->type = JELLYFISH_FSON_TYPE_BOOL;
    v->u.boolean = val;
    return 1;
}

int fossil_ai_jellyfish_fson_make_object(fossil_ai_jellyfish_fson_value_t *v) {
    if (!v) return -1;

    if (v->type == JELLYFISH_FSON_TYPE_OBJECT) {
        /* If already empty object, nothing to do */
        if (v->u.object.count == 0)
            return 0;

        /* Free existing children then re-init */
        for (size_t i = 0; i < v->u.object.count; ++i) {
            if (v->u.object.values[i]) {
                fossil_ai_jellyfish_fson_reset(v->u.object.values[i]);
                free(v->u.object.values[i]);
                v->u.object.values[i] = NULL;
            }
            v->u.object.keys[i][0] = '\0';
        }
        v->u.object.count = 0;
        return 1;
    }

    /* Different type: reset (will free owned resources) then build object */
    if (v->type != JELLYFISH_FSON_TYPE_NULL)
        fossil_ai_jellyfish_fson_reset(v); /* sets to NULL */

    memset(v, 0, sizeof(*v));
    v->type = JELLYFISH_FSON_TYPE_OBJECT;
    v->u.object.count = 0;
    return 1;
}

int fossil_ai_jellyfish_fson_make_array(fossil_ai_jellyfish_fson_value_t *v) {
    if (!v) return -1;

    if (v->type == JELLYFISH_FSON_TYPE_ARRAY) {
        if (v->u.array.count == 0)
            return 0;

        for (size_t i = 0; i < v->u.array.count; ++i) {
            if (v->u.array.items[i]) {
                fossil_ai_jellyfish_fson_reset(v->u.array.items[i]);
                free(v->u.array.items[i]);
                v->u.array.items[i] = NULL;
            }
        }
        v->u.array.count = 0;
        return 1;
    }

    if (v->type != JELLYFISH_FSON_TYPE_NULL)
        fossil_ai_jellyfish_fson_reset(v);

    memset(v, 0, sizeof(*v));
    v->type = JELLYFISH_FSON_TYPE_ARRAY;
    v->u.array.count = 0;
    return 1;
}

int fossil_ai_jellyfish_fson_object_put(fossil_ai_jellyfish_fson_value_t *obj,
                                        const char *key,
                                        fossil_ai_jellyfish_fson_value_t *value)
{
    if (!obj || !key || !value)
        return -1;

    /* Ensure object type (auto-promote NULL to OBJECT) */
    if (obj->type != JELLYFISH_FSON_TYPE_OBJECT) {
        if (obj->type == JELLYFISH_FSON_TYPE_NULL) {
            if (fossil_ai_jellyfish_fson_make_object(obj) < 0)
                return -2;
        } else {
            /* Reset then make object */
            fossil_ai_jellyfish_fson_reset(obj);
            if (fossil_ai_jellyfish_fson_make_object(obj) < 0)
                return -2;
        }
    }

    /* Trim leading/trailing whitespace */
    const char *start = key;
    while (*start && (*start == ' ' || *start == '\t' || *start == '\n' || *start == '\r'))
        start++;
    size_t len = strlen(start);
    while (len &&
           (start[len - 1] == ' ' || start[len - 1] == '\t' ||
            start[len - 1] == '\n' || start[len - 1] == '\r'))
        len--;

    if (len == 0 || len >= FOSSIL_JELLYFISH_FSON_KEY_SIZE)
        return -3;

    /* Search for existing key */
    size_t count = obj->u.object.count;
    for (size_t i = 0; i < count; ++i) {
        if (strncmp(obj->u.object.keys[i], start, FOSSIL_JELLYFISH_FSON_KEY_SIZE) == 0 &&
            strlen(obj->u.object.keys[i]) == len) {
            /* Existing key */
            if (obj->u.object.values[i] == value)
                return 0; /* no-op (same pointer) */

            /* Replace: free old subtree */
            if (obj->u.object.values[i]) {
                fossil_ai_jellyfish_fson_reset(obj->u.object.values[i]);
                free(obj->u.object.values[i]);
            }
            obj->u.object.values[i] = value;
            return 1;
        }
    }

    /* New key */
    if (count >= FOSSIL_JELLYFISH_FSON_MAX_OBJECT)
        return -4;

    /* Store key */
    memcpy(obj->u.object.keys[count], start, len);
    obj->u.object.keys[count][len] = '\0';
    obj->u.object.values[count] = value;
    obj->u.object.count = count + 1;
    return 1;
}

fossil_ai_jellyfish_fson_value_t *fossil_ai_jellyfish_fson_object_get(const fossil_ai_jellyfish_fson_value_t *obj,
                                    const char *key)
{
    if (!obj || !key) return NULL;
    if (obj->type != JELLYFISH_FSON_TYPE_OBJECT) return NULL;

    /* Trim leading / trailing whitespace (mirror put semantics) */
    while (*key && (*key == ' ' || *key == '\t' || *key == '\n' || *key == '\r'))
        key++;
    size_t len = strlen(key);
    while (len &&
           (key[len - 1] == ' ' || key[len - 1] == '\t' ||
            key[len - 1] == '\n' || key[len - 1] == '\r'))
        len--;

    if (len == 0 || len >= FOSSIL_JELLYFISH_FSON_KEY_SIZE)
        return NULL;

    for (size_t i = 0; i < obj->u.object.count; ++i) {
        if (obj->u.object.keys[i][0] == '\0')
            continue;
        /* Fast length check before strcmp */
        if (strlen(obj->u.object.keys[i]) != len)
            continue;
        if (strncmp(obj->u.object.keys[i], key, len) == 0)
            return obj->u.object.values[i];
    }
    return NULL;
}

int fossil_ai_jellyfish_fson_array_push(fossil_ai_jellyfish_fson_value_t *arr,
                                        fossil_ai_jellyfish_fson_value_t *value) {
    if (!arr || !value) return -1;

    if (arr->type != JELLYFISH_FSON_TYPE_ARRAY) {
        if (arr->type == JELLYFISH_FSON_TYPE_NULL) {
            if (fossil_ai_jellyfish_fson_make_array(arr) < 0)
                return -1;
        } else {
            fossil_ai_jellyfish_fson_reset(arr);
            if (fossil_ai_jellyfish_fson_make_array(arr) < 0)
                return -1;
        }
    }

    if (arr->u.array.count >= FOSSIL_JELLYFISH_FSON_MAX_ARRAY)
        return -2;

    arr->u.array.items[arr->u.array.count++] = value;
    return 1;
}

/**
 * Get array element.
 * Complexity: O(1)
 */
fossil_ai_jellyfish_fson_value_t *
fossil_ai_jellyfish_fson_array_get(const fossil_ai_jellyfish_fson_value_t *arr,
                                   size_t index) {
    if (!arr) return NULL;
    if (arr->type != JELLYFISH_FSON_TYPE_ARRAY) return NULL;
    if (index >= arr->u.array.count) return NULL;
    return arr->u.array.items[index];
}

/**
 * Length of array.
 * Complexity: O(1)
 */
size_t fossil_ai_jellyfish_fson_array_length(const fossil_ai_jellyfish_fson_value_t *arr) {
    if (!arr) return 0;
    if (arr->type != JELLYFISH_FSON_TYPE_ARRAY) return 0;
    return arr->u.array.count;
}

int fossil_ai_jellyfish_fson_copy(const fossil_ai_jellyfish_fson_value_t *src,
                                  fossil_ai_jellyfish_fson_value_t *dst) {
    if (!src || !dst) return -1;
    if (src == dst) return 1;

    /* Start with a clean destination */
    fossil_ai_jellyfish_fson_reset(dst);

    dst->type = src->type;

    switch (src->type) {
        case JELLYFISH_FSON_TYPE_NULL:
            break;

        /* Plain scalars (direct copy) */
        case JELLYFISH_FSON_TYPE_BOOL:      dst->u.boolean = src->u.boolean; break;
        case JELLYFISH_FSON_TYPE_I8:        dst->u.i8 = src->u.i8; break;
        case JELLYFISH_FSON_TYPE_I16:       dst->u.i16 = src->u.i16; break;
        case JELLYFISH_FSON_TYPE_I32:       dst->u.i32 = src->u.i32; break;
        case JELLYFISH_FSON_TYPE_I64:       dst->u.i64 = src->u.i64; break;
        case JELLYFISH_FSON_TYPE_U8:        dst->u.u8 = src->u.u8; break;
        case JELLYFISH_FSON_TYPE_U16:       dst->u.u16 = src->u.u16; break;
        case JELLYFISH_FSON_TYPE_U32:       dst->u.u32 = src->u.u32; break;
        case JELLYFISH_FSON_TYPE_U64:       dst->u.u64 = src->u.u64; break;
        case JELLYFISH_FSON_TYPE_F32:       dst->u.f32 = src->u.f32; break;
        case JELLYFISH_FSON_TYPE_F64:       dst->u.f64 = src->u.f64; break;
        case JELLYFISH_FSON_TYPE_OCT:       dst->u.oct = src->u.oct; break;
        case JELLYFISH_FSON_TYPE_HEX:       dst->u.hex = src->u.hex; break;
        case JELLYFISH_FSON_TYPE_BIN:       dst->u.bin = src->u.bin; break;
        case JELLYFISH_FSON_TYPE_CHAR:      dst->u.character = src->u.character; break;
        case JELLYFISH_FSON_TYPE_DATETIME:  dst->u.datetime.epoch_ns = src->u.datetime.epoch_ns; break;
        case JELLYFISH_FSON_TYPE_DURATION:  dst->u.duration.ns = src->u.duration.ns; break;

        case JELLYFISH_FSON_TYPE_CSTR:
            if (src->u.cstr) {
                size_t len = strlen(src->u.cstr);
                dst->u.cstr = (char *)malloc(len + 1);
                if (!dst->u.cstr) { fossil_ai_jellyfish_fson_reset(dst); return -2; }
                memcpy(dst->u.cstr, src->u.cstr, len + 1);
            } else {
                dst->u.cstr = NULL;
            }
            break;

        case JELLYFISH_FSON_TYPE_ENUM:
            dst->u.enum_val.allowed = src->u.enum_val.allowed;
            dst->u.enum_val.allowed_count = src->u.enum_val.allowed_count;
            if (src->u.enum_val.symbol) {
                size_t len = strlen(src->u.enum_val.symbol);
                dst->u.enum_val.symbol = (char *)malloc(len + 1);
                if (!dst->u.enum_val.symbol) { fossil_ai_jellyfish_fson_reset(dst); return -2; }
                memcpy(dst->u.enum_val.symbol, src->u.enum_val.symbol, len + 1);
            } else {
                dst->u.enum_val.symbol = NULL;
            }
            break;

        case JELLYFISH_FSON_TYPE_ARRAY: {
            dst->u.array.count = 0;
            for (size_t i = 0; i < src->u.array.count; ++i) {
                const fossil_ai_jellyfish_fson_value_t *schild = src->u.array.items[i];
                if (!schild) {
                    dst->u.array.items[i] = NULL;
                    continue;
                }
                fossil_ai_jellyfish_fson_value_t *dchild =
                    (fossil_ai_jellyfish_fson_value_t *)malloc(sizeof(*dchild));
                if (!dchild) { fossil_ai_jellyfish_fson_reset(dst); return -2; }
                memset(dchild, 0, sizeof(*dchild));
                if (fossil_ai_jellyfish_fson_copy(schild, dchild) < 0) {
                    free(dchild);
                    fossil_ai_jellyfish_fson_reset(dst);
                    return -2;
                }
                dst->u.array.items[i] = dchild;
                dst->u.array.count++;
            }
            break;
        }

        case JELLYFISH_FSON_TYPE_OBJECT: {
            dst->u.object.count = 0;
            for (size_t i = 0; i < src->u.object.count; ++i) {
                fossil_ai_jellyfish_fson_value_t *dchild =
                    (fossil_ai_jellyfish_fson_value_t *)malloc(sizeof(*dchild));
                if (!dchild) { fossil_ai_jellyfish_fson_reset(dst); return -2; }
                memset(dchild, 0, sizeof(*dchild));
                if (fossil_ai_jellyfish_fson_copy(src->u.object.values[i], dchild) < 0) {
                    free(dchild);
                    fossil_ai_jellyfish_fson_reset(dst);
                    return -2;
                }
                strncpy(dst->u.object.keys[i],
                        src->u.object.keys[i],
                        FOSSIL_JELLYFISH_FSON_KEY_SIZE - 1);
                dst->u.object.keys[i][FOSSIL_JELLYFISH_FSON_KEY_SIZE - 1] = '\0';
                dst->u.object.values[i] = dchild;
                dst->u.object.count++;
            }
            break;
        }

        default:
            /* Unknown type fallback: treat as NULL */
            dst->type = JELLYFISH_FSON_TYPE_NULL;
            break;
    }

    return 1;
}

void fossil_ai_jellyfish_fson_free(fossil_ai_jellyfish_fson_value_t *v) {
    if (!v) return;
    fossil_ai_jellyfish_fson_reset(v);
}

/* -------------------------- Block FSON Attachments ------------------------- */

int fossil_ai_jellyfish_block_set_semantic_kv(fossil_ai_jellyfish_block_t *block,
                                              const char *key,
                                              fossil_ai_jellyfish_fson_value_t *value)
{
    if (!block || !key || !value) return -1;

    fossil_ai_jellyfish_fson_value_t *root = &block->classify.semantic_meta;

    /* Ensure root is an OBJECT (auto-promote NULL). */
    if (root->type == JELLYFISH_FSON_TYPE_NULL) {
        if (fossil_ai_jellyfish_fson_make_object(root) < 0)
            return -2;
    } else if (root->type != JELLYFISH_FSON_TYPE_OBJECT) {
        /* Replace incompatible type with a fresh OBJECT. */
        fossil_ai_jellyfish_fson_reset(root);
        if (fossil_ai_jellyfish_fson_make_object(root) < 0)
            return -2;
    }

    int rc = fossil_ai_jellyfish_fson_object_put(root, key, value);
    if (rc == 1) {
        /* Added/replaced -> update timing metadata. */
        uint64_t now = get_time_microseconds();
        if (block->time.timestamp == 0)
            block->time.timestamp = now;
        uint64_t prev = block->time.updated_at ?
                        block->time.updated_at : block->time.timestamp;
        block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
        block->time.updated_at = now;
    }
    return rc;
}

int fossil_ai_jellyfish_block_add_attachment(fossil_ai_jellyfish_block_t *block,
                                             fossil_ai_jellyfish_fson_value_t *attachment)
{
    if (!block || !attachment)
        return -1;

    fossil_ai_jellyfish_block_fson_t *fs = &block->fson;

    /* Duplicate pointer check */
    for (size_t i = 0; i < fs->attachment_count; ++i) {
        if (fs->attachments[i] == attachment)
            return 0; /* unchanged */
    }

    if (fs->attachment_count >= FOSSIL_JELLYFISH_FSON_MAX_ARRAY)
        return -2;

    fs->attachments[fs->attachment_count++] = attachment;

    /* Update timing metadata */
    uint64_t now = get_time_microseconds();
    if (block->time.timestamp == 0)
        block->time.timestamp = now;
    uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;
    block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
    block->time.updated_at = now;

    return 1;
}

int fossil_ai_jellyfish_block_set_audit_meta(fossil_ai_jellyfish_block_t *block,
                                             fossil_ai_jellyfish_fson_value_t *meta)
{
    if (!block || !meta) return -1;

    /* Reset previous audit_meta if present and different pointer */
    if (block->audit_meta.type != JELLYFISH_FSON_TYPE_NULL && &block->audit_meta != meta) {
        fossil_ai_jellyfish_fson_reset(&block->audit_meta);
    }

    /* Deep copy meta into block->audit_meta */
    if (&block->audit_meta != meta) {
        if (fossil_ai_jellyfish_fson_copy(meta, &block->audit_meta) < 0)
            return -2;
    }

    /* Update timing metadata */
    uint64_t now = get_time_microseconds();
    if (block->time.timestamp == 0)
        block->time.timestamp = now;
    uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;
    block->time.delta_ms = (uint32_t)((now - prev) / 1000ULL);
    block->time.updated_at = now;

    return 1;
}

/* --------------------------- Chain-level FSON Meta ------------------------- */

int fossil_ai_jellyfish_repo_meta_put(fossil_ai_jellyfish_chain_t *chain,
                                      const char *key,
                                      fossil_ai_jellyfish_fson_value_t *value)
{
    if (!chain || !key || !value) return -1;

    fossil_ai_jellyfish_fson_value_t *root = &chain->repo_meta;

    /* Ensure OBJECT root (auto-promote or replace incompatible type) */
    if (root->type == JELLYFISH_FSON_TYPE_NULL) {
        if (fossil_ai_jellyfish_fson_make_object(root) < 0)
            return -2;
    } else if (root->type != JELLYFISH_FSON_TYPE_OBJECT) {
        fossil_ai_jellyfish_fson_reset(root);
        if (fossil_ai_jellyfish_fson_make_object(root) < 0)
            return -2;
    }

    int rc = fossil_ai_jellyfish_fson_object_put(root, key, value);
    if (rc == 1) {
        chain->updated_at = get_time_microseconds();
    }
    return rc;
}

/* ---------------------------- Cryptographic Ops --------------------------- */

int fossil_ai_jellyfish_block_sign(fossil_ai_jellyfish_block_t *block, const uint8_t *priv_key) {
    if (!block || !priv_key) return -1;
    if (!block->attributes.valid ||
        block->io.input_len == 0 ||
        block->io.output_len == 0) return -2;

    /* Build two 32-byte digests to fill 64-byte signature slot */
    uint8_t digest1[FOSSIL_JELLYFISH_HASH_SIZE];
    uint8_t digest2[FOSSIL_JELLYFISH_HASH_SIZE];

    /* Canonical-ish serialization parts */
    char buf1[ FOSSIL_JELLYFISH_INPUT_SIZE + FOSSIL_JELLYFISH_OUTPUT_SIZE + 96 ];
    char buf2[ FOSSIL_JELLYFISH_INPUT_SIZE + FOSSIL_JELLYFISH_OUTPUT_SIZE + 96 ];

    /* Serialize parent hashes (up to 4) compactly as hex prefixes (first 4 bytes each) */
    char parents_hex[4 * 8 + 1];
    size_t phw = 0;
    for (size_t p = 0; p < block->identity.parent_count && p < 4; ++p) {
        for (int k = 0; k < 4; ++k)
            sprintf(parents_hex + phw, "%02X", block->identity.parent_hashes[p][k]);
        phw += 8;
    }
    parents_hex[phw] = '\0';

    /* First buffer: priv_key[0..15] + commit hash + input + output + parents */
    size_t off = 0;
    for (int i = 0; i < 16; ++i) {
        sprintf(buf1 + off, "%02X", priv_key[i]);
        off += 2;
    }
    for (int i = 0; i < 8; ++i) { /* first 8 bytes commit hash */
        sprintf(buf1 + off, "%02X", block->identity.commit_hash[i]);
        off += 2;
    }
    buf1[off] = '|'; off++;
    strncpy(buf1 + off, block->io.input, FOSSIL_JELLYFISH_INPUT_SIZE - 1);
    off += block->io.input_len;
    buf1[off] = '|'; off++;
    strncpy(buf1 + off, block->io.output, FOSSIL_JELLYFISH_OUTPUT_SIZE - 1);
    off += block->io.output_len;
    buf1[off] = '|'; off++;
    strncpy(buf1 + off, parents_hex, sizeof(parents_hex) - 1);
    off = strnlen(buf1, sizeof(buf1));
    buf1[off] = '\0';

    /* Second buffer: priv_key[16..31] + tree hash + output + input + block_type */
    off = 0;
    for (int i = 16; i < 32; ++i) {
        sprintf(buf2 + off, "%02X", priv_key[i]);
        off += 2;
    }
    for (int i = 0; i < 8; ++i) { /* first 8 bytes tree hash */
        sprintf(buf2 + off, "%02X", block->identity.tree_hash[i]);
        off += 2;
    }
    buf2[off] = '|'; off++;
    strncpy(buf2 + off, block->io.output, FOSSIL_JELLYFISH_OUTPUT_SIZE - 1);
    off += block->io.output_len;
    buf2[off] = '|'; off++;
    strncpy(buf2 + off, block->io.input, FOSSIL_JELLYFISH_INPUT_SIZE - 1);
    off += block->io.input_len;
    off += snprintf(buf2 + off, sizeof(buf2) - off, "|%u", (unsigned)block->block_type);
    buf2[sizeof(buf2)-1] = '\0';

    fossil_ai_jellyfish_hash(buf1, buf2, digest1);
    fossil_ai_jellyfish_hash(buf2, buf1, digest2);

    /* If signature already matches, no change */
    if (block->identity.signature_len == FOSSIL_SIGNATURE_SIZE &&
        memcmp(block->identity.signature, digest1, 32) == 0 &&
        memcmp(block->identity.signature + 32, digest2, 32) == 0) {
        return 0;
    }

    memcpy(block->identity.signature, digest1, 32);
    memcpy(block->identity.signature + 32, digest2, 32);
    block->identity.signature_len = FOSSIL_SIGNATURE_SIZE;

    /* Mark as signed/trusted */
    if (block->block_type != JELLY_COMMIT_SIGNED)
        block->block_type = JELLY_COMMIT_SIGNED;
    block->attributes.trusted = 1;
    if (block->attributes.confidence < 0.95f)
        block->attributes.confidence = 0.95f;

    /* Timestamp update */
    uint64_t now = get_time_microseconds();
    if (block->time.timestamp == 0) block->time.timestamp = now;
    uint64_t prev = block->time.updated_at ? block->time.updated_at : block->time.timestamp;
    block->time.delta_ms = (uint32_t)((now - prev)/1000ULL);
    block->time.updated_at = now;

    return 1;
}

bool fossil_ai_jellyfish_block_verify_signature(const fossil_ai_jellyfish_block_t *block,
                                                const uint8_t *pub_key) {
    if (!block || !pub_key) return false;
    if (!block->attributes.valid) return false;
    if (block->identity.signature_len != FOSSIL_SIGNATURE_SIZE) return false;
    if (block->io.input_len == 0 || block->io.output_len == 0) return false;

    uint8_t digest1[FOSSIL_JELLYFISH_HASH_SIZE];
    uint8_t digest2[FOSSIL_JELLYFISH_HASH_SIZE];

    char buf1[FOSSIL_JELLYFISH_INPUT_SIZE + FOSSIL_JELLYFISH_OUTPUT_SIZE + 96];
    char buf2[FOSSIL_JELLYFISH_INPUT_SIZE + FOSSIL_JELLYFISH_OUTPUT_SIZE + 96];

    /* Parents hex (first 4 bytes each -> 8 hex chars) */
    char parents_hex[4 * 8 + 1];
    size_t phw = 0;
    for (size_t p = 0; p < block->identity.parent_count && p < 4; ++p) {
        for (int k = 0; k < 4; ++k)
            sprintf(parents_hex + phw, "%02X", block->identity.parent_hashes[p][k]);
        phw += 8;
    }
    parents_hex[phw] = '\0';

    /* buf1: pub_key[0..15] + first 8 bytes commit hash + |input|output|parents */
    size_t off = 0;
    for (int i = 0; i < 16; ++i) {
        sprintf(buf1 + off, "%02X", pub_key[i]);
        off += 2;
    }
    for (int i = 0; i < 8; ++i) {
        sprintf(buf1 + off, "%02X", block->identity.commit_hash[i]);
        off += 2;
    }
    buf1[off++] = '|';
    strncpy(buf1 + off, block->io.input, FOSSIL_JELLYFISH_INPUT_SIZE - 1);
    off += block->io.input_len;
    buf1[off++] = '|';
    strncpy(buf1 + off, block->io.output, FOSSIL_JELLYFISH_OUTPUT_SIZE - 1);
    off += block->io.output_len;
    buf1[off++] = '|';
    strncpy(buf1 + off, parents_hex, sizeof(parents_hex) - 1);
    off = strnlen(buf1, sizeof(buf1));
    buf1[off] = '\0';

    /* buf2: pub_key[16..31] + first 8 bytes tree hash + |output|input|type */
    off = 0;
    for (int i = 16; i < 32; ++i) {
        sprintf(buf2 + off, "%02X", pub_key[i]);
        off += 2;
    }
    for (int i = 0; i < 8; ++i) {
        sprintf(buf2 + off, "%02X", block->identity.tree_hash[i]);
        off += 2;
    }
    buf2[off++] = '|';
    strncpy(buf2 + off, block->io.output, FOSSIL_JELLYFISH_OUTPUT_SIZE - 1);
    off += block->io.output_len;
    buf2[off++] = '|';
    strncpy(buf2 + off, block->io.input, FOSSIL_JELLYFISH_INPUT_SIZE - 1);
    off += block->io.input_len;
    off += snprintf(buf2 + off, sizeof(buf2) - off, "|%u", (unsigned)block->block_type);
    buf2[sizeof(buf2)-1] = '\0';

    fossil_ai_jellyfish_hash(buf1, buf2, digest1);
    fossil_ai_jellyfish_hash(buf2, buf1, digest2);

    if (memcmp(block->identity.signature, digest1, 32) != 0) return false;
    if (memcmp(block->identity.signature + 32, digest2, 32) != 0) return false;
    return true;
}

/* ------------------------------ Tokenization ------------------------------- */

size_t fossil_ai_jellyfish_tokenize(const char *input,
                                    char tokens[][FOSSIL_JELLYFISH_TOKEN_SIZE],
                                    size_t max_tokens)
{
    if (!input || !tokens || max_tokens == 0)
        return 0;

    size_t count = 0;
    size_t i = 0;
    char tok[FOSSIL_JELLYFISH_TOKEN_SIZE];
    size_t tlen = 0;
    int in_token = 0;

    while (input[i] != '\0') {
        unsigned char c = (unsigned char)input[i];
        int is_alnum = (c >= '0' && c <= '9') ||
                       (c >= 'A' && c <= 'Z') ||
                       (c >= 'a' && c <= 'z');

        if (is_alnum) {
            if (!in_token) {
                in_token = 1;
                tlen = 0;
            }
            if (tlen + 1 < FOSSIL_JELLYFISH_TOKEN_SIZE) {
                if (c >= 'A' && c <= 'Z') c = (unsigned char)(c - 'A' + 'a');
                tok[tlen++] = (char)c;
            } /* else: silently drop extra chars of an overlong token */
        } else {
            if (in_token) {
                tok[tlen] = '\0';
                if (count < max_tokens) {
                    strncpy(tokens[count], tok, FOSSIL_JELLYFISH_TOKEN_SIZE);
                    tokens[count][FOSSIL_JELLYFISH_TOKEN_SIZE - 1] = '\0';
                    count++;
                    if (count == max_tokens)
                        return count;
                } else {
                    return count;
                }
                in_token = 0;
            }
        }
        i++;
    }

    /* Flush trailing token */
    if (in_token && count < max_tokens) {
        tok[tlen] = '\0';
        strncpy(tokens[count], tok, FOSSIL_JELLYFISH_TOKEN_SIZE);
        tokens[count][FOSSIL_JELLYFISH_TOKEN_SIZE - 1] = '\0';
        count++;
    }

    return count;
}

/* ------------------------------- Cloning ----------------------------------- */

int fossil_ai_jellyfish_clone_chain(const fossil_ai_jellyfish_chain_t *src,
                                    fossil_ai_jellyfish_chain_t *dst) {
    if (!src || !dst) return -1;

    memset(dst, 0, sizeof(*dst));

    /* Copy basic scalars */
    dst->count        = src->count;
    dst->created_at   = src->created_at;
    dst->updated_at   = src->updated_at;
    memcpy(dst->repo_id, src->repo_id, FOSSIL_DEVICE_ID_SIZE);
    strncpy(dst->default_branch, src->default_branch, sizeof(dst->default_branch)-1);

    /* Clone repo_meta */
    fossil_ai_jellyfish_fson_init(&dst->repo_meta);
    if (fossil_ai_jellyfish_fson_copy(&src->repo_meta, &dst->repo_meta) < 0)
        return -2;

    /* Branches */
    dst->branch_count = src->branch_count;
    if (dst->branch_count > FOSSIL_JELLYFISH_MAX_BRANCHES)
        dst->branch_count = FOSSIL_JELLYFISH_MAX_BRANCHES;
    for (size_t b = 0; b < dst->branch_count; ++b) {
        memcpy(dst->branches[b].name, src->branches[b].name, sizeof(dst->branches[b].name));
        memcpy(dst->branches[b].head_hash, src->branches[b].head_hash, FOSSIL_JELLYFISH_HASH_SIZE);
        fossil_ai_jellyfish_fson_init(&dst->branches[b].branch_meta);
        if (fossil_ai_jellyfish_fson_copy(&src->branches[b].branch_meta,
                                          &dst->branches[b].branch_meta) < 0)
            return -2;
    }

    int valid_cloned = 0;

    /* Commits */
    size_t upper = FOSSIL_JELLYFISH_MAX_MEM;
    if (dst->count > upper) dst->count = upper;

    for (size_t i = 0; i < upper; ++i) {
        const fossil_ai_jellyfish_block_t *sb = &src->commits[i];
        fossil_ai_jellyfish_block_t *db = &dst->commits[i];

        if (!sb->attributes.valid && sb->time.timestamp == 0) {
            /* Unused slot -> leave zeroed */
            continue;
        }

        /* Shallow copy POD fields first (will neutralize FSON sub-values afterwards) */
        *db = *sb;

        /* Re-init & deep copy FSON: semantic_meta */
        fossil_ai_jellyfish_fson_init(&db->classify.semantic_meta);
        if (fossil_ai_jellyfish_fson_copy(&sb->classify.semantic_meta,
                                          &db->classify.semantic_meta) < 0)
            return -2;

        /* IO meta */
        fossil_ai_jellyfish_fson_init(&db->io.io_meta);
        if (fossil_ai_jellyfish_fson_copy(&sb->io.io_meta,
                                          &db->io.io_meta) < 0)
            return -2;

        /* Root fson */
        fossil_ai_jellyfish_fson_init(&db->fson.root);
        if (fossil_ai_jellyfish_fson_copy(&sb->fson.root,
                                          &db->fson.root) < 0)
            return -2;

        /* Audit meta */
        fossil_ai_jellyfish_fson_init(&db->audit_meta);
        if (fossil_ai_jellyfish_fson_copy(&sb->audit_meta,
                                          &db->audit_meta) < 0)
            return -2;

        /* Attachments (each is an owned subtree) */
        db->fson.attachment_count = 0;
        for (size_t a = 0; a < sb->fson.attachment_count &&
                               a < FOSSIL_JELLYFISH_FSON_MAX_ARRAY; ++a) {
            fossil_ai_jellyfish_fson_value_t *satt = sb->fson.attachments[a];
            if (!satt) {
                db->fson.attachments[a] = NULL;
                continue;
            }
            fossil_ai_jellyfish_fson_value_t *datt =
                (fossil_ai_jellyfish_fson_value_t *)malloc(sizeof(*datt));
            if (!datt) return -2;
            fossil_ai_jellyfish_fson_init(datt);
            if (fossil_ai_jellyfish_fson_copy(satt, datt) < 0) {
                fossil_ai_jellyfish_fson_reset(datt);
                free(datt);
                return -2;
            }
            db->fson.attachments[a] = datt;
            db->fson.attachment_count++;
        }

        if (db->attributes.valid)
            valid_cloned++;
    }

    return valid_cloned;
}
