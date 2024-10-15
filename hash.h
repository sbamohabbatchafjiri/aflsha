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
   american fuzzy lop - optimized hashing function
   -----------------------------------------------
   This is an optimized version of the original lightweight_hash32 function,
   aiming to improve performance while maintaining reasonable hash quality for fuzzing.
*/

#ifndef _HAVE_HASH_H
#define _HAVE_HASH_H

#include "types.h"
#include <stdint.h>

#ifdef __x86_64__

// Define rotation macros for 64-bit and 32-bit systems
#define ROL64(x, n) ((x << n) | (x >> (64 - n)))  // Rotate left macro for 64-bit

// Optimized Keccak-like constants for mixing (using fewer rounds)
static const u64 ROUNDS[3] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL
};

// Optimized lightweight SHA-3 hash function with reduced rotations and simpler constants
static inline u32 hash32(const void* key, u32 len, u32 seed) {
    const u64* data = (const u64*)key;
    u64 h1 = seed ^ len;

    len >>= 3;  // Process in 64-bit chunks

    // Optimized mixing loop with fewer rounds and simpler constants
    for (u32 i = 0; i < len; ++i) {
        u64 k1 = data[i];

        // Single constant for mixing and fewer bit rotations for better performance
        k1 ^= ROUNDS[i % 3];
        k1 = ROL64(k1, 13);  // Reduced rotation from 21 bits to 13 bits
        h1 ^= k1;
        h1 = ROL64(h1, 9);   // Reduced rotation from 17 bits to 9 bits
        h1 *= 0x1b873593;    // Use simpler constant for mixing
    }

    // Final simple diffusion (simplified SHA-3-like finalization)
    h1 ^= h1 >> 15;  // Reduced shift value for faster diffusion
    h1 *= 0xff51afd7ed558ccdULL;
    h1 ^= h1 >> 15;

    // Return 32-bit hash result by XORing upper and lower halves
    return (u32)(h1 ^ (h1 >> 32));
}

#else 

// Define rotation macro for 32-bit systems
#define ROL32(_x, _r)  ((((u32)(_x)) << (_r)) | (((u32)(_x)) >> (32 - (_r))))

// Optimized 32-bit hash function based on MurmurHash3 with reduced complexity
static inline u32 hash32(const void* key, u32 len, u32 seed) {
    const u32* data = (const u32*)key;
    u32 h1 = seed ^ len;

    len >>= 2;  // Process in 32-bit chunks

    // Optimized mixing loop for 32-bit blocks with reduced rotation
    for (u32 i = 0; i < len; ++i) {
        u32 k1 = data[i];
        k1 *= 0xcc9e2d51;  // Use the same constant as MurmurHash3
        k1 = ROL32(k1, 13);  // Reduced rotation from 15 bits to 13 bits
        k1 *= 0x1b873593;

        h1 ^= k1;
        h1 = ROL32(h1, 7);   // Reduced rotation for faster execution
        h1 = h1 * 5 + 0xe6546b64;
    }

    // Final mixing steps for diffusion (same as MurmurHash3 but optimized)
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1;
}

#endif /* ^__x86_64__ */

#endif /* !_HAVE_HASH_H */
