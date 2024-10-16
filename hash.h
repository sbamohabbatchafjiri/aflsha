/*
  Copyright 2016 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - hashing function
   -------------------------------------

   The hash32() function is a variant of MurmurHash3, a good
   non-cryptosafe hashing function developed by Austin Appleby.

   For simplicity, this variant does *NOT* accept buffer lengths
   that are not divisible by 8 bytes. The 32-bit version is otherwise
   similar to the original; the 64-bit one is a custom hack with
   mostly-unproven properties.

   Austin's original code is public domain.

   Other code written and maintained by Michal Zalewski <lcamtuf@google.com>
*/
#ifndef _HAVE_HASH_H
#define _HAVE_HASH_H

#include "types.h"
#include <stdint.h>

#ifdef __x86_64__

#define ROL64(x, n) ((x << n) | (x >> (64 - n)))  // Rotate left macro

// Keccak-like constants for mixing and permutation
static const u64 KECCAK_ROUNDS[5] = {
    0x428a2f98d728ae22ULL,
    0x7137449123ef65cdULL,
    0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL
};

// Keccak-like hash for 64-bit systems
static inline u32 hash32(const void* key, u32 len, u32 seed) {
    const u64* data = (const u64*)key;
    u64 h1 = seed ^ len;

    len >>= 3;  // Process in 64-bit chunks

    // Unrolled loop to improve performance
    while (len >= 4) {
        u64 k1 = *data++;
        k1 ^= KECCAK_ROUNDS[0];
        k1 = ROL64(k1, 21);
        k1 ^= KECCAK_ROUNDS[1];
        
        h1 ^= k1;
        h1 = ROL64(h1, 17);
        h1 *= 0x52dce729;

        k1 = *data++;
        k1 ^= KECCAK_ROUNDS[2];
        k1 = ROL64(k1, 21);
        k1 ^= KECCAK_ROUNDS[3];
        
        h1 ^= k1;
        h1 = ROL64(h1, 17);
        h1 *= 0x52dce729;

        k1 = *data++;
        k1 ^= KECCAK_ROUNDS[4];
        k1 = ROL64(k1, 21);
        k1 ^= KECCAK_ROUNDS[0];
        
        h1 ^= k1;
        h1 = ROL64(h1, 17);
        h1 *= 0x52dce729;

        k1 = *data++;
        k1 ^= KECCAK_ROUNDS[1];
        k1 = ROL64(k1, 21);
        k1 ^= KECCAK_ROUNDS[2];
        
        h1 ^= k1;
        h1 = ROL64(h1, 17);
        h1 *= 0x52dce729;

        len -= 4;
    }

    // Process remaining blocks
    while (len--) {
        u64 k1 = *data++;
        k1 ^= KECCAK_ROUNDS[len % 5];
        k1 = ROL64(k1, 21);
        k1 ^= KECCAK_ROUNDS[(len + 1) % 5];

        h1 ^= k1;
        h1 = ROL64(h1, 17);
        h1 *= 0x52dce729;
    }

    // Final rounds of diffusion (like SHA-3's finalization)
    h1 ^= h1 >> 29;
    h1 *= 0xff51afd7ed558ccdULL;
    h1 ^= h1 >> 33;
    h1 *= 0xc4ceb9fe1a85ec53ULL;
    h1 ^= h1 >> 33;

    return (u32)(h1 ^ (h1 >> 32));
}

#else 

#define ROL32(_x, _r)  ((((u32)(_x)) << (_r)) | (((u32)(_x)) >> (32 - (_r))))

// MurmurHash3-like function for 32-bit systems
static inline u32 hash32(const void* key, u32 len, u32 seed) {
    const u32* data = (const u32*)key;
    u32 h1 = seed ^ len;

    len >>= 2;  // Process in 32-bit chunks

    while (len--) {
        u32 k1 = *data++;
        k1 *= 0xcc9e2d51;
        k1 = ROL32(k1, 15);
        k1 *= 0x1b873593;

        h1 ^= k1;
        h1 = ROL32(h1, 13);
        h1 = h1 * 5 + 0xe6546b64;
    }

    // Final avalanche mixing
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

#endif /* ^__x86_64__ */

#endif /* !_HAVE_HASH_H */
