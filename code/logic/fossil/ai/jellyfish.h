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
#ifndef FOSSIL_JELLYFISH_AI_H
#define FOSSIL_JELLYFISH_AI_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <float.h>
#include <time.h>
#include <math.h>

enum {
    FOSSIL_JELLYFISH_MAX_MEM          = 128,
    FOSSIL_JELLYFISH_HASH_SIZE        = 32,
    FOSSIL_JELLYFISH_INPUT_SIZE       = 64,
    FOSSIL_JELLYFISH_OUTPUT_SIZE      = 64,
    FOSSIL_JELLYFISH_MAX_MODELS       = 32,
    FOSSIL_JELLYFISH_MAX_TOKENS       = 16,
    FOSSIL_JELLYFISH_TOKEN_SIZE       = 16,
    FOSSIL_JELLYFISH_MAX_MODEL_FILES  = 16,
    FOSSIL_JELLYFISH_MAX_TAGS         = 8
};

#define FOSSIL_DEVICE_ID_SIZE      16   // E.g., 128-bit hardware ID
#define FOSSIL_SIGNATURE_SIZE      64   // ECDSA, ED25519, etc.
#define FOSSIL_JELLYFISH_MAX_LINKS 4

#ifdef __cplusplus
extern "C"
{
#endif

// *****************************************************************************
// Type definitions
// *****************************************************************************

/**
 * @brief Enumerates the types of memory blocks in Truthful Intelligence.
 *
 * These types help categorize the origin, validation, and purpose of a block.
 */
typedef enum {
    JELLY_BLOCK_UNKNOWN = 0,           // Default/unclassified block
    JELLY_BLOCK_OBSERVED = 1,          // Raw input/output from real-world interaction
    JELLY_BLOCK_INFERRED = 2,          // Derived from reasoning or extrapolated logic
    JELLY_BLOCK_VALIDATED = 3,         // Confirmed by external source (e.g., consensus or signature)
    JELLY_BLOCK_CORRECTED = 4,         // Modified by user or verifier to fix prior output
    JELLY_BLOCK_ASSUMED = 5,           // Presumed true due to lack of contradiction (but not verified)
    JELLY_BLOCK_RETRACTED = 6,         // Marked as invalid or superseded (soft deletion)
    JELLY_BLOCK_EXPERIMENTAL = 7,      // From test/hypothesis, not to be trusted by default
    JELLY_BLOCK_GUIDED = 8,            // User-directed insertion (manual memory, prompts, etc.)
    JELLY_BLOCK_IMMUTABLE = 9,         // Permanent/trusted system-level assertion
    JELLY_BLOCK_ARCHIVED = 10          // Frozen due to age, stability, or inactivity
} fossil_jellyfish_block_type_t;

/**
 * Block Attributes - Flags or enumerations for block attributes
 */
typedef struct {
    int immutable;            // 1 = block is immutable, 0 = mutable
    int valid;                // 1 = block data is valid, 0 = invalid or corrupted
    float confidence;         // Confidence score for block's content
    uint32_t usage_count;     // Number of times this block was referenced/used
    int pruned;               // 1 = block has been pruned/marked for removal, 0 = active
    int redacted;             // 1 = block has been redacted, 0 = original
    int deduplicated;         // 1 = block is a deduplicated copy, 0 = unique/original
    int compressed;           // 1 = block has been compressed, 0 = uncompressed
    int expired;              // 1 = block is expired, 0 = valid
    int trusted;              // 1 = block is trusted (e.g., signature verified), 0 = untrusted
    int conflicted;           // 1 = block is in conflict with another, 0 = no conflict
    int reserved;             // Reserved for future use (set to 0)
} fossil_jellyfish_block_attributes_t;

/**
 * Block Timing Information
 */
typedef struct {
    uint64_t timestamp;       // Epoch time when block was created/learned
    uint32_t delta_ms;        // Time delta since previous block (ms)
    uint32_t duration_ms;     // Duration of processing/input (ms)
    uint64_t updated_at;      // Last modification timestamp (epoch ms)
    uint64_t expires_at;      // Expiry timestamp (epoch ms), 0 if not set
    uint64_t validated_at;    // When block was last validated (epoch ms), 0 if never
} fossil_jellyfish_block_time_t;

/**
 * Block Identification and Security
 */
typedef struct {
    uint8_t hash[FOSSIL_JELLYFISH_HASH_SIZE];         // Cryptographic fingerprint of block
    uint8_t device_id[FOSSIL_DEVICE_ID_SIZE];         // Device where block was created
    uint8_t signature[FOSSIL_SIGNATURE_SIZE];         // Digital signature for integrity/authentication
    uint32_t block_index;                             // Index of this block in the chain
    uint32_t prev_block_index;                        // Index of previous block (for linking/history)
    uint8_t prev_hash[FOSSIL_JELLYFISH_HASH_SIZE];    // Hash of previous block (for chain integrity)
    uint32_t signature_len;                           // Actual length of signature (if variable)
    uint32_t reserved;                                // Reserved for future use (set to 0)
} fossil_jellyfish_block_identity_t;

/**
 * Block Classification / Reasoning Info
 */
typedef struct {
    // Primary logical origin (legacy, main derivation)
    uint32_t derived_from_index;

    // Multiple cross-references to other blocks (multi-hop graph edges)
    uint32_t cross_refs[FOSSIL_JELLYFISH_MAX_LINKS];
    size_t cross_ref_count;

    // Forward references (blocks that derive from this one)
    uint32_t forward_refs[FOSSIL_JELLYFISH_MAX_LINKS];
    size_t forward_ref_count;

    // reasoning metadata
    uint16_t reasoning_depth;      // How far from original observation this block is
    uint16_t reserved;

    char classification_reason[128];
    char tags[FOSSIL_JELLYFISH_MAX_TAGS][32];
    float similarity_score;
    int is_hallucinated;
    int is_contradicted;
} fossil_jellyfish_block_classification_t;

/**
 * Core Input/Output Data
 */
typedef struct {
    char input[FOSSIL_JELLYFISH_INPUT_SIZE];      // Input string (question, prompt, etc.)
    char output[FOSSIL_JELLYFISH_OUTPUT_SIZE];    // Output string (answer, response, etc.)
    size_t input_len;                             // Actual length of input (excluding null terminator)
    size_t output_len;                            // Actual length of output (excluding null terminator)
    char input_tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];   // Tokenized input
    size_t input_token_count;                     // Number of input tokens
    char output_tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];  // Tokenized output
    size_t output_token_count;                    // Number of output tokens
    int compressed;                               // 1 if input/output is compressed, 0 otherwise
    int redacted;                                 // 1 if input/output is redacted, 0 otherwise
    int reserved;                                 // Reserved for future use (set to 0)
} fossil_jellyfish_block_io_t;

/**
 * Complete Jellyfish Memory Block
 */
typedef struct {
    fossil_jellyfish_block_io_t io;                       // Input/output pair
    fossil_jellyfish_block_identity_t identity;           // Hash, device, signature
    fossil_jellyfish_block_time_t time;                   // Timing metadata
    fossil_jellyfish_block_attributes_t attributes;       // Flags and confidence
    fossil_jellyfish_block_type_t block_type;             // Type enum
    fossil_jellyfish_block_classification_t classify;     // Classification info (instead of imagination)
} fossil_jellyfish_block_t;

/**
 * Represents a chain of jellyfish blocks.
 */
typedef struct {
    fossil_jellyfish_block_t memory[FOSSIL_JELLYFISH_MAX_MEM];
    size_t count;

    uint8_t device_id[FOSSIL_DEVICE_ID_SIZE];  // For file I/O and ownership
    uint64_t created_at;                       // Chain creation timestamp
    uint64_t updated_at;                       // Last update timestamp
} fossil_jellyfish_chain_t;

// *****************************************************************************
// Function prototypes
// *****************************************************************************

/**
 * Generate a hash for the given input and output.
 * This computes a hash based on the input and output strings.
 * 
 * @param input The input string to hash.
 * @param output The output string to hash.
 * @param hash_out Pointer to an array where the resulting hash will be stored.
 */
void fossil_jellyfish_hash(const char *input, const char *output, uint8_t *hash_out);

/**
 * Initialize the jellyfish chain.
 * This sets up the initial state of the chain.
 * 
 * @param chain Pointer to the jellyfish chain to initialize.
 */
void fossil_jellyfish_init(fossil_jellyfish_chain_t *chain);

/**
 * Learn a new input-output pair.
 * This adds a new block to the chain with the given input and output.
 * 
 * @param chain Pointer to the jellyfish chain.
 * @param input The input string to learn.
 * @param output The output string corresponding to the input.
 */
void fossil_jellyfish_learn(fossil_jellyfish_chain_t *chain, const char *input, const char *output);

/**
 * Find a block by its hash.
 * This searches the chain for a block with the given hash.
 * 
 * @param chain Pointer to the jellyfish chain.
 * @param hash The hash to search for.
 * @return Pointer to the found block, or NULL if not found.
 */
void fossil_jellyfish_remove(fossil_jellyfish_chain_t *chain, size_t index);

/**
 * Find a block by its hash.
 * This searches the chain for a block with the given hash.
 * 
 * @param chain Pointer to the jellyfish chain.
 * @param hash The hash to search for.
 * @return Pointer to the found block, or NULL if not found.
 */
fossil_jellyfish_block_t *fossil_jellyfish_find(fossil_jellyfish_chain_t *chain, const uint8_t *hash);

/**
 * Update an existing block in the jellyfish chain.
 * This modifies the input and output of a specific block.
 * 
 * @param chain Pointer to the jellyfish chain.
 * @param index The index of the block to update.
 * @param input The new input string.
 * @param output The new output string.
 */
void fossil_jellyfish_update(fossil_jellyfish_chain_t *chain, size_t index, const char *input, const char *output);

/**
 * @brief Save a Jellyfish chain to a binary file.
 *
 * The function writes a fixed-format binary serialization of the entire chain,
 * including a magic header and version number for format validation.
 *
 * @param chain Pointer to the Jellyfish chain structure to serialize.
 * @param filepath File path where to save the binary data.
 * @return 0 on success, negative value on failure.
 */
int fossil_jellyfish_save(const fossil_jellyfish_chain_t *chain, const char *filepath);

/**
 * @brief Load a Jellyfish chain from a binary file.
 *
 * The function reads a fixed-format binary serialization and reconstructs
 * the entire chain, verifying the magic header and version.
 *
 * @param chain Pointer to the Jellyfish chain structure to populate.
 * @param filepath File path from which to load the binary data.
 * @return 0 on success, negative value on failure.
 */
int fossil_jellyfish_load(fossil_jellyfish_chain_t *chain, const char *filepath);

/**
 * Cleanup the jellyfish chain.
 * This removes old or invalid blocks from the chain to reclaim space.
 * 
 * @param chain Pointer to the jellyfish chain to clean up.
 */
void fossil_jellyfish_cleanup(fossil_jellyfish_chain_t *chain);

/**
 * @brief Audits the jellyfish chain for anomalies, inconsistencies, or suspicious patterns.
 *
 * This function scans the chain for duplicate hashes, invalid timestamps, low-confidence blocks,
 * signature mismatches, or other integrity issues. It prints a report to stdout and returns the
 * number of issues found.
 *
 * @param chain Pointer to the jellyfish chain to audit.
 * @return Number of issues detected.
 */
int fossil_jellyfish_audit(const fossil_jellyfish_chain_t *chain);

/**
 * @brief Prunes the jellyfish chain by removing invalid, expired, or low-confidence blocks.
 *
 * This function iterates through the chain and removes blocks that are no longer valid,
 * have expired, or fall below a specified confidence threshold.
 *
 * @param chain Pointer to the jellyfish chain to prune.
 * @param min_confidence Minimum confidence required to retain a block.
 * @return Number of blocks pruned.
 */
int fossil_jellyfish_prune(fossil_jellyfish_chain_t *chain, float min_confidence);

/**
 * Reason about an input.
 * This searches the chain for a matching input and returns the corresponding output.
 * 
 * @param chain Pointer to the jellyfish chain.
 * @param input The input string to reason about.
 * @return The output string if found, or "Unknown" if not found.
 */
const char* fossil_jellyfish_reason(fossil_jellyfish_chain_t *chain, const char *input);

/**
 * Dump the contents of the jellyfish chain.
 * This prints the current state of the chain to standard output.
 * 
 * @param chain Pointer to the jellyfish chain to dump.
 */
void fossil_jellyfish_dump(const fossil_jellyfish_chain_t *chain);

/**
 * Decay the confidence of the jellyfish chain.
 * This reduces the confidence of all blocks in the chain by a specified decay rate.
 * 
 * @param chain Pointer to the jellyfish chain.
 * @param decay_rate The rate at which to decay confidence (0.0 - 1.0).
 */
void fossil_jellyfish_decay_confidence(fossil_jellyfish_chain_t *chain, float decay_rate);

/**
 * Tokenizes a given input string into lowercase word tokens.
 *
 * @param input       Null-terminated string to tokenize.
 * @param tokens      2D array to store output tokens (each max FOSSIL_JELLYFISH_TOKEN_SIZE).
 * @param max_tokens  Maximum number of tokens to extract.
 * @return            The number of tokens actually written to the tokens array.
 */
size_t fossil_jellyfish_tokenize(const char *input, char tokens[][FOSSIL_JELLYFISH_TOKEN_SIZE], size_t max_tokens);

/**
 * Returns a pointer to the memory block in the chain with the highest confidence score.
 *
 * @param chain  Pointer to the memory chain.
 * @return       Pointer to the best fossil_jellyfish_block_t, or NULL if no valid memory exists.
 */
const fossil_jellyfish_block_t *fossil_jellyfish_best_memory(const fossil_jellyfish_chain_t *chain);

/**
 * Calculates a normalized score representing how "full" or utilized the knowledge base is.
 *
 * @param chain  Pointer to the memory chain.
 * @return       Float between 0.0 and 1.0 indicating knowledge coverage.
 */
float fossil_jellyfish_knowledge_coverage(const fossil_jellyfish_chain_t *chain);

/**
 * Checks if adding a given input-output pair would contradict existing memory.
 *
 * @param chain   Pointer to the memory chain.
 * @param input   Input to check.
 * @param output  Output to check.
 * @return        1 if a conflict is found, 0 otherwise.
 */
int fossil_jellyfish_detect_conflict(const fossil_jellyfish_chain_t *chain, const char *input, const char *output);

/**
 * Prints a self-reflection report of the current memory chain to stdout.
 * Includes memory size, confidence distribution, usage patterns, and top entries.
 *
 * @param chain  Pointer to the memory chain to reflect on.
 */
void fossil_jellyfish_reflect(const fossil_jellyfish_chain_t *chain);

/**
 * Verifies the integrity of a jellyfish block.
 * This checks if the block has valid input, output, and hash.
 * 
 * @param block Pointer to the jellyfish block to verify.
 * @return True if the block is valid, false otherwise.
 */
bool fossil_jellyfish_verify_block(const fossil_jellyfish_block_t* block);

/**
 * @brief Prints a validation report for each memory block in the Jellyfish chain.
 *
 * Iterates through the chain and invokes `fossil_jellyfish_verify_block` on each valid block,
 * outputting a status line for each entry to standard output.
 *
 * This helps in debugging chain integrity, visualizing where corruption or verification
 * failures occur, and understanding the structure of the chain.
 *
 * @param chain Pointer to the Jellyfish chain to validate.
 */
void fossil_jellyfish_validation_report(const fossil_jellyfish_chain_t *chain);

/**
 * @brief Performs full-chain validation by verifying each block.
 *
 * Calls `fossil_jellyfish_verify_block` for every block in the chain and returns
 * false if any verification fails.
 *
 * This function is useful for asserting the integrity of a deserialized chain,
 * checking for tampering, or before accepting input from external sources.
 *
 * @param chain Pointer to the Jellyfish chain to verify.
 * @return true if all blocks pass verification, false otherwise.
 */
bool fossil_jellyfish_verify_chain(const fossil_jellyfish_chain_t *chain);

/**
 * @brief Computes a normalized trust score for the Jellyfish chain.
 *
 * Only includes valid and immutable blocks in the scoring. Confidence values from
 * eligible blocks are averaged to produce a floating-point trust score from 0.0 to 1.0.
 *
 * This metric can help determine the chain’s overall credibility, for instance before
 * deploying, merging, or persisting long-term knowledge.
 *
 * @param chain Pointer to the Jellyfish chain to analyze.
 * @return Trust score (0.0f to 1.0f), or 0.0f if the chain is null or has no valid entries.
 */
float fossil_jellyfish_chain_trust_score(const fossil_jellyfish_chain_t *chain);

/**
 * @brief Marks a Jellyfish memory block as immutable.
 *
 * This flag indicates that the block should not be altered or pruned, and will be
 * included in trust score calculations. Immutable blocks are useful for storing core
 * logic, critical responses, or verified inputs that must persist through decay or pruning.
 *
 * @param block Pointer to the memory block to mark as immutable.
 */
void fossil_jellyfish_mark_immutable(fossil_jellyfish_block_t *block);

/**
 * @brief Deduplicates blocks with identical input/output pairs.
 * @param chain The jellyfish memory chain.
 * @return Number of duplicates removed.
 */
int fossil_jellyfish_deduplicate_chain(fossil_jellyfish_chain_t *chain);

/**
 * @brief Compresses the memory chain by trimming whitespace and optionally shrinking fields.
 * @param chain The jellyfish memory chain.
 * @return Number of blocks modified.
 */
int fossil_jellyfish_compress_chain(fossil_jellyfish_chain_t *chain);

/**
 * @brief Finds the best matching memory block in the chain for a given input string.
 * 
 * It selects the most confident valid response, favoring immutable blocks if tied,
 * and optionally factoring in future enhancements like string similarity or recency.
 * 
 * @param chain The Jellyfish chain to search.
 * @param input The input string to match.
 * @return Pointer to the best matching block, or NULL if none found.
 */
const fossil_jellyfish_block_t* fossil_jellyfish_best_match(const fossil_jellyfish_chain_t *chain, const char *input);

/**
 * @brief Redacts sensitive data in a memory block while retaining structural integrity.
 *
 * Overwrites the input and/or output fields with fixed tokens (e.g. "***REDACTED***").
 * May be used before public export or sharing across systems.
 *
 * @param block Pointer to the block to redact.
 * @return 0 on success, non-zero on error.
 */
int fossil_jellyfish_redact_block(fossil_jellyfish_block_t *block);

/**
 * @brief Computes statistics over the Jellyfish chain.
 *
 * Populates out parameters with stats like count, valid count, confidence mean,
 * trust score, block age distribution, and immutable ratio.
 *
 * @param chain Pointer to the chain to analyze.
 * @param out_valid_count Pointer to store number of valid blocks.
 * @param out_avg_confidence Pointer to store average confidence score.
 * @param out_immutable_ratio Pointer to store immutable block ratio.
 */
void fossil_jellyfish_chain_stats(const fossil_jellyfish_chain_t *chain, size_t out_valid_count[5], float out_avg_confidence[5], float out_immutable_ratio[5]);

/**
 * @brief Compares two Jellyfish chains and identifies block-level differences.
 *
 * May be used for verifying synchronization, deduplication between devices,
 * or forensic audits (e.g., tampering or divergence).
 *
 * @param a First chain.
 * @param b Second chain.
 * @return Number of differing blocks, or -1 on error.
 */
int fossil_jellyfish_compare_chains(const fossil_jellyfish_chain_t *a, const fossil_jellyfish_chain_t *b);

/**
 * @brief Computes a single fingerprint hash for the entire chain.
 *
 * Hashes block hashes, timestamps, and content summary to produce a deterministic
 * digest for the chain’s current state.
 *
 * @param chain The Jellyfish chain to hash.
 * @param out_hash Output buffer of FOSSIL_JELLYFISH_HASH_SIZE bytes.
 */
void fossil_jellyfish_chain_fingerprint(const fossil_jellyfish_chain_t *chain, uint8_t *out_hash);

/**
 * @brief Trims the chain to retain only the N most recently used or most confident blocks.
 *
 * Used for constrained environments or audit-controlled exports.
 *
 * @param chain The Jellyfish chain.
 * @param max_blocks Number of blocks to retain.
 * @return Number of blocks removed.
 */
int fossil_jellyfish_trim(fossil_jellyfish_chain_t *chain, size_t max_blocks);

/**
 * @brief Reorders valid blocks to the front of the chain and removes gaps.
 *
 * Maintains block order by timestamp and shrinks memory footprint after pruning or trimming.
 *
 * @param chain The Jellyfish chain.
 * @return Number of blocks moved.
 */
int fossil_jellyfish_chain_compact(fossil_jellyfish_chain_t *chain);

/**
 * @brief Computes the age of a block relative to current time.
 *
 * @param block The memory block.
 * @param now   Current UNIX timestamp.
 * @return      Age in milliseconds.
 */
uint64_t fossil_jellyfish_block_age(const fossil_jellyfish_block_t *block, uint64_t now);

/**
 * @brief Returns a short diagnostic string for a block.
 *
 * Outputs a line including input, output, confidence, usage, and trust status.
 * Useful for human-readable debug tools or logging systems.
 *
 * @param block The block to describe.
 * @param out   Output buffer.
 * @param size  Size of the buffer.
 */
void fossil_jellyfish_block_explain(const fossil_jellyfish_block_t *block, char *out, size_t size);

/**
 * @brief Finds a memory block by its hash.
 *
 * @param chain The Jellyfish chain.
 * @param hash  The 32-byte hash to search for.
 * @return Pointer to the matching block, or NULL.
 */
const fossil_jellyfish_block_t *fossil_jellyfish_find_by_hash(const fossil_jellyfish_chain_t *chain, const uint8_t *hash);

/**
 * @brief Creates a deep copy of a Jellyfish chain.
 *
 * @param src Source chain.
 * @param dst Destination chain.
 * @return 0 on success, non-zero on error.
 */
int fossil_jellyfish_clone_chain(const fossil_jellyfish_chain_t *src, fossil_jellyfish_chain_t *dst);

/**
 * @brief Like `reason`, but includes match confidence, source block, and hash.
 *
 * Useful for debug, inspection, or high-trust outputs.
 *
 * @param chain  Pointer to the memory chain.
 * @param input  Input string to reason with.
 * @param out_output  Output string buffer.
 * @param out_confidence Optional confidence return pointer.
 * @param out_block Optional pointer to store matching block.
 * @return True if a match was found, false otherwise.
 */
bool fossil_jellyfish_reason_verbose(const fossil_jellyfish_chain_t *chain, const char *input, char *out_output, float *out_confidence, const fossil_jellyfish_block_t **out_block);

/**
 * @brief Signs a Jellyfish block using a private key.
 * @param block The block to sign.
 * @param priv_key The private key (implementation-defined).
 * @return 0 on success.
 */
int fossil_jellyfish_block_sign(fossil_jellyfish_block_t *block, const uint8_t *priv_key);

/**
 * @brief Verifies a Jellyfish block's signature.
 * @param block The block to verify.
 * @param pub_key The public key.
 * @return True if signature is valid.
 */
bool fossil_jellyfish_block_verify_signature(const fossil_jellyfish_block_t *block, const uint8_t *pub_key);

#ifdef __cplusplus
}
#include <stdexcept>
#include <cstdint>
#include <vector>
#include <array>
#include <string>

namespace fossil {

namespace ai {

    // C++ wrapper for the jellyfish AI
    class Jellyfish {
    public:
        /**
         * @brief Generates a hash for the given input and output.
         *
         * @param input The input string to hash.
         * @param output The output string to hash.
         * @param hash_out Pointer to an array where the resulting hash will be stored.
         */
        static void hash(const char* input, const char* output, uint8_t* hash_out) {
            ::fossil_jellyfish_hash(input, output, hash_out);
        }

        /**
         * @brief Initializes the jellyfish chain.
         */
        void init() {
            ::fossil_jellyfish_init(&chain_);
        }

        /**
         * @brief Learns a new input-output pair.
         *
         * @param input The input string to learn.
         * @param output The output string corresponding to the input.
         */
        void learn(const char* input, const char* output) {
            ::fossil_jellyfish_learn(&chain_, input, output);
        }

        /**
         * @brief Removes a block at the specified index.
         *
         * @param index The index of the block to remove.
         */
        void remove(size_t index) {
            ::fossil_jellyfish_remove(&chain_, index);
        }

        /**
         * @brief Finds a block by its hash.
         *
         * @param hash The hash to search for.
         * @return Pointer to the found block, or nullptr if not found.
         */
        fossil_jellyfish_block_t* find(const uint8_t* hash) {
            return ::fossil_jellyfish_find(&chain_, hash);
        }

        /**
         * @brief Updates an existing block in the jellyfish chain.
         *
         * @param index The index of the block to update.
         * @param input The new input string.
         * @param output The new output string.
         */
        void update(size_t index, const char* input, const char* output) {
            ::fossil_jellyfish_update(&chain_, index, input, output);
        }

        /**
         * @brief Saves the Jellyfish chain to a binary file.
         *
         * @param filepath File path where to save the binary data.
         * @return 0 on success, negative value on failure.
         */
        int save(const char* filepath) const {
            return ::fossil_jellyfish_save(&chain_, filepath);
        }

        /**
         * @brief Loads the Jellyfish chain from a binary file.
         *
         * @param filepath File path from which to load the binary data.
         * @return 0 on success, negative value on failure.
         */
        int load(const char* filepath) {
            return ::fossil_jellyfish_load(&chain_, filepath);
        }

        /**
         * @brief Cleans up the jellyfish chain by removing old or invalid blocks.
         */
        void cleanup() {
            ::fossil_jellyfish_cleanup(&chain_);
        }

        /**
         * @brief Audits the jellyfish chain for anomalies or inconsistencies.
         *
         * @return Number of issues detected.
         */
        int audit() const {
            return ::fossil_jellyfish_audit(&chain_);
        }

        /**
         * @brief Prunes the jellyfish chain by removing invalid, expired, or low-confidence blocks.
         *
         * @param min_confidence Minimum confidence required to retain a block.
         * @return Number of blocks pruned.
         */
        int prune(float min_confidence) {
            return ::fossil_jellyfish_prune(&chain_, min_confidence);
        }

        /**
         * @brief Reasons about an input and returns the corresponding output.
         *
         * @param input The input string to reason about.
         * @return The output string if found, or "Unknown" if not found.
         */
        const char* reason(const char* input) {
            return ::fossil_jellyfish_reason(&chain_, input);
        }

        /**
         * @brief Dumps the contents of the jellyfish chain to standard output.
         */
        void dump() const {
            ::fossil_jellyfish_dump(&chain_);
        }

        /**
         * @brief Decays the confidence of all blocks in the jellyfish chain.
         *
         * @param decay_rate The rate at which to decay confidence (0.0 - 1.0).
         */
        void decay_confidence(float decay_rate) {
            ::fossil_jellyfish_decay_confidence(&chain_, decay_rate);
        }

        /**
         * @brief Tokenizes a given input string into lowercase word tokens.
         *
         * @param input       Null-terminated string to tokenize.
         * @param tokens      2D array to store output tokens (each max FOSSIL_JELLYFISH_TOKEN_SIZE).
         * @param max_tokens  Maximum number of tokens to extract.
         * @return            The number of tokens actually written to the tokens array.
         */
        size_t tokenize(const char* input, char tokens[][FOSSIL_JELLYFISH_TOKEN_SIZE], size_t max_tokens) const {
            return ::fossil_jellyfish_tokenize(input, tokens, max_tokens);
        }

        /**
         * @brief Returns a pointer to the memory block in the chain with the highest confidence score.
         *
         * @return Pointer to the best fossil_jellyfish_block_t, or nullptr if no valid memory exists.
         */
        const fossil_jellyfish_block_t* best_memory() const {
            return ::fossil_jellyfish_best_memory(&chain_);
        }

        /**
         * @brief Calculates a normalized score representing how "full" or utilized the knowledge base is.
         *
         * @return Float between 0.0 and 1.0 indicating knowledge coverage.
         */
        float knowledge_coverage() const {
            return ::fossil_jellyfish_knowledge_coverage(&chain_);
        }

        /**
         * @brief Checks if adding a given input-output pair would contradict existing memory.
         *
         * @param input   Input to check.
         * @param output  Output to check.
         * @return        1 if a conflict is found, 0 otherwise.
         */
        int detect_conflict(const char* input, const char* output) const {
            return ::fossil_jellyfish_detect_conflict(&chain_, input, output);
        }

        /**
         * @brief Prints a self-reflection report of the current memory chain to stdout.
         */
        void reflect() const {
            ::fossil_jellyfish_reflect(&chain_);
        }

        /**
         * @brief Verifies the integrity of a jellyfish block.
         *
         * @param block Pointer to the jellyfish block to verify.
         * @return True if the block is valid, false otherwise.
         */
        static bool verify_block(const fossil_jellyfish_block_t* block) {
            return ::fossil_jellyfish_verify_block(block);
        }

        /**
         * @brief Prints a validation report for each memory block in the Jellyfish chain.
         */
        void validation_report() const {
            ::fossil_jellyfish_validation_report(&chain_);
        }

        /**
         * @brief Performs full-chain validation by verifying each block.
         *
         * @return true if all blocks pass verification, false otherwise.
         */
        bool verify_chain() const {
            return ::fossil_jellyfish_verify_chain(&chain_);
        }

        /**
         * @brief Computes a normalized trust score for the Jellyfish chain.
         *
         * @return Trust score (0.0f to 1.0f), or 0.0f if the chain is null or has no valid entries.
         */
        float chain_trust_score() const {
            return ::fossil_jellyfish_chain_trust_score(&chain_);
        }

        /**
         * @brief Marks a Jellyfish memory block as immutable.
         *
         * @param block Pointer to the memory block to mark as immutable.
         */
        static void mark_immutable(fossil_jellyfish_block_t* block) {
            ::fossil_jellyfish_mark_immutable(block);
        }

        /**
         * @brief Deduplicates blocks with identical input/output pairs.
         * @return Number of duplicates removed.
         */
        int deduplicate_chain() {
            return ::fossil_jellyfish_deduplicate_chain(&chain_);
        }

        /**
         * @brief Compresses the memory chain by trimming whitespace and optionally shrinking fields.
         * @return Number of blocks modified.
         */
        int compress_chain() {
            return ::fossil_jellyfish_compress_chain(&chain_);
        }

        /**
         * @brief Finds the best matching memory block in the chain for a given input string.
         * @param input The input string to match.
         * @return Pointer to the best matching block, or nullptr if none found.
         */
        const fossil_jellyfish_block_t* best_match(const char* input) const {
            return ::fossil_jellyfish_best_match(&chain_, input);
        }

        /**
         * @brief Redacts sensitive data in a memory block while retaining structural integrity.
         * @param block Pointer to the block to redact.
         * @return 0 on success, non-zero on error.
         */
        static int redact_block(fossil_jellyfish_block_t* block) {
            return ::fossil_jellyfish_redact_block(block);
        }

        /**
         * @brief Computes statistics over the Jellyfish chain.
         *
         * Populates out parameters with stats like count, valid count, confidence mean,
         * trust score, block age distribution, and immutable ratio.
         *
         * @param out_valid_count Pointer to store number of valid blocks.
         * @param out_avg_confidence Pointer to store average confidence score.
         * @param out_immutable_ratio Pointer to store immutable block ratio.
         */
        void chain_stats(size_t out_valid_count[5], float out_avg_confidence[5], float out_immutable_ratio[5]) const {
            ::fossil_jellyfish_chain_stats(&chain_, out_valid_count, out_avg_confidence, out_immutable_ratio);
        }

        /**
         * @brief Compares this Jellyfish chain with another and identifies block-level differences.
         *
         * @param other The other Jellyfish chain to compare with.
         * @return Number of differing blocks, or -1 on error.
         */
        int compare_chains(const Jellyfish& other) const {
            return ::fossil_jellyfish_compare_chains(&chain_, &other.chain_);
        }

        /**
         * @brief Computes a single fingerprint hash for the entire chain.
         *
         * @param out_hash Output buffer of FOSSIL_JELLYFISH_HASH_SIZE bytes.
         */
        void chain_fingerprint(uint8_t *out_hash) const {
            ::fossil_jellyfish_chain_fingerprint(&chain_, out_hash);
        }

        /**
         * @brief Trims the chain to retain only the N most recently used or most confident blocks.
         *
         * @param max_blocks Number of blocks to retain.
         * @return Number of blocks removed.
         */
        int trim(size_t max_blocks) {
            return ::fossil_jellyfish_trim(&chain_, max_blocks);
        }

        /**
         * @brief Reorders valid blocks to the front of the chain and removes gaps.
         *
         * @return Number of blocks moved.
         */
        int chain_compact() {
            return ::fossil_jellyfish_chain_compact(&chain_);
        }

        /**
         * @brief Computes the age of a block relative to current time.
         *
         * @param block The memory block.
         * @param now   Current UNIX timestamp.
         * @return      Age in milliseconds.
         */
        static uint64_t block_age(const fossil_jellyfish_block_t* block, uint64_t now) {
            return ::fossil_jellyfish_block_age(block, now);
        }

        /**
         * @brief Returns a short diagnostic string for a block.
         *
         * @param block The block to describe.
         * @param out   Output buffer.
         * @param size  Size of the buffer.
         */
        static void block_explain(const fossil_jellyfish_block_t* block, char* out, size_t size) {
            ::fossil_jellyfish_block_explain(block, out, size);
        }

        /**
         * @brief Finds a memory block by its hash.
         *
         * @param hash  The 32-byte hash to search for.
         * @return Pointer to the matching block, or nullptr.
         */
        const fossil_jellyfish_block_t* find_by_hash(const uint8_t* hash) const {
            return ::fossil_jellyfish_find_by_hash(&chain_, hash);
        }

        /**
         * @brief Creates a deep copy of a Jellyfish chain.
         *
         * @param dst Destination chain.
         * @return 0 on success, non-zero on error.
         */
        int clone_chain(Jellyfish& dst) const {
            return ::fossil_jellyfish_clone_chain(&chain_, &dst.chain_);
        }

        /**
         * @brief Like `reason`, but includes match confidence, source block, and hash.
         *
         * @param input         Input string to reason with.
         * @param out_output    Output string buffer.
         * @param out_confidence Optional confidence return pointer.
         * @param out_block     Optional pointer to store matching block.
         * @return True if a match was found, false otherwise.
         */
        bool reason_verbose(const char* input, char* out_output, float* out_confidence, const fossil_jellyfish_block_t** out_block) const {
            return ::fossil_jellyfish_reason_verbose(&chain_, input, out_output, out_confidence, out_block);
        }

        /**
         * @brief Signs a Jellyfish block using a private key.
         * @param block The block to sign.
         * @param priv_key The private key (implementation-defined).
         * @return 0 on success.
         */
        static int block_sign(fossil_jellyfish_block_t* block, const uint8_t* priv_key) {
            return ::fossil_jellyfish_block_sign(block, priv_key);
        }

        /**
         * @brief Verifies a Jellyfish block's signature.
         * @param block The block to verify.
         * @param pub_key The public key.
         * @return True if signature is valid.
         */
        static bool block_verify_signature(const fossil_jellyfish_block_t* block, const uint8_t* pub_key) {
            return ::fossil_jellyfish_block_verify_signature(block, pub_key);
        }

        /**
         * @brief Returns a pointer to the native jellyfish chain structure.
         * 
         * This is useful for low-level operations or interfacing with C code.
         * 
         * @return Pointer to the native jellyfish chain.
         */
        fossil_jellyfish_chain_t* native_chain() { return &chain_; }

        /**
         * @brief Returns a const pointer to the native jellyfish chain structure.
         * 
         * This is useful for low-level operations or interfacing with C code.
         * 
         * @return Const pointer to the native jellyfish chain.
         */
        const fossil_jellyfish_chain_t* native_chain() const { return &chain_; }

    private:
        fossil_jellyfish_chain_t chain_;
    };

} // namespace ai

} // namespace fossil

#endif

#endif /* fossil_fish_FRAMEWORK_H */
