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
    FOSSIL_JELLYFISH_MAX_TAGS         = 8,
    FOSSIL_JELLYFISH_MAX_BRANCHES      = 8
};

#define FOSSIL_DEVICE_ID_SIZE      16   // E.g., 128-bit hardware ID
#define FOSSIL_SIGNATURE_SIZE      64   // ECDSA, ED25519, etc.
#define FOSSIL_JELLYFISH_MAX_LINKS 4

#ifdef __cplusplus
extern "C"
{
#endif

// *****************************************************************************
// Type definitions — Jellyfish AI Git-Chain Hybrid
// *****************************************************************************

/**
 * @brief Enumerates commit types for the Jellyfish AI Git-chain hybrid.
 *
 * These types model how knowledge evolves, diverges, merges, and stabilizes,
 * mirroring Git operations while preserving AI reasoning intent.
 */
typedef enum {
    // -----------------------------------------------------------------
    // Core commits — foundational and reasoning states
    // -----------------------------------------------------------------
    JELLY_COMMIT_UNKNOWN = 0,          // Undefined or placeholder commit
    JELLY_COMMIT_INIT = 1,             // Genesis or initial commit in a chain
    JELLY_COMMIT_OBSERVE = 2,          // Observation or raw data intake
    JELLY_COMMIT_INFER = 3,            // Logical derivation or reasoning commit
    JELLY_COMMIT_VALIDATE = 4,         // Verified or confirmed (trusted) result
    JELLY_COMMIT_PATCH = 5,            // Correction or manual hotfix commit

    // -----------------------------------------------------------------
    // Branching and merging — reasoning paths and reconciliation
    // -----------------------------------------------------------------
    JELLY_COMMIT_BRANCH = 10,          // Divergent reasoning path or hypothesis branch
    JELLY_COMMIT_MERGE = 11,           // Merge of two or more reasoning lines
    JELLY_COMMIT_REBASE = 12,          // Rebased logic onto new foundation
    JELLY_COMMIT_CHERRY_PICK = 13,     // Selective logic adoption (copy commit)
    JELLY_COMMIT_FORK = 14,            // Forked repository / cloned memory state

    // -----------------------------------------------------------------
    // Tagging, releases, and archival
    // -----------------------------------------------------------------
    JELLY_COMMIT_TAG = 20,             // Stable tagged version (snapshot)
    JELLY_COMMIT_RELEASE = 21,         // Publicly declared stable reasoning state
    JELLY_COMMIT_ARCHIVE = 22,         // Frozen, immutable version
    JELLY_COMMIT_SNAPSHOT = 23,        // Temporary snapshot (autosave/checkpoint)

    // -----------------------------------------------------------------
    // Experimental and ephemeral states
    // -----------------------------------------------------------------
    JELLY_COMMIT_EXPERIMENT = 30,      // Experimental reasoning branch
    JELLY_COMMIT_STASH = 31,           // Temporary hold or deferred logic
    JELLY_COMMIT_DRAFT = 32,           // Work-in-progress state (unvalidated)
    JELLY_COMMIT_REVERT = 33,          // Undo/reversal of prior commit
    JELLY_COMMIT_ROLLBACK = 34,        // Forced rollback (AI self-correction)

    // -----------------------------------------------------------------
    // Collaboration, synchronization, and meta-commits
    // -----------------------------------------------------------------
    JELLY_COMMIT_SYNC = 40,            // Synced with external node or agent
    JELLY_COMMIT_MIRROR = 41,          // Mirrored repository state
    JELLY_COMMIT_IMPORT = 42,          // Imported external dataset or logic
    JELLY_COMMIT_EXPORT = 43,          // Exported memory snapshot
    JELLY_COMMIT_SIGNED = 44,          // Verified signed commit (authoritative)
    JELLY_COMMIT_REVIEW = 45,          // Peer-reviewed or audited commit

    // -----------------------------------------------------------------
    // Special and terminal states
    // -----------------------------------------------------------------
    JELLY_COMMIT_DETACHED = 50,        // Detached HEAD / isolated reasoning path
    JELLY_COMMIT_ABANDONED = 51,       // Dropped or deprecated branch
    JELLY_COMMIT_CONFLICT = 52,        // Conflict-resolving commit
    JELLY_COMMIT_PRUNE = 53,           // Commit pruned from history
    JELLY_COMMIT_FINAL = 54            // Terminal or end-of-life commit
} fossil_ai_jellyfish_commit_type_t;

/* ---------------------------------------------------------------------------
 * Jellyfish FSON v2: Lightweight Value Types (adapted for fossil_ai_jellyfish_)
 * Static-capacity containers to match Jellyfish embedded style (no realloc).
 * --------------------------------------------------------------------------- */
typedef enum {
    JELLYFISH_FSON_TYPE_NULL = 0,
    JELLYFISH_FSON_TYPE_BOOL,

    /* Explicit scalar types */
    JELLYFISH_FSON_TYPE_I8,
    JELLYFISH_FSON_TYPE_I16,
    JELLYFISH_FSON_TYPE_I32,
    JELLYFISH_FSON_TYPE_I64,
    JELLYFISH_FSON_TYPE_U8,
    JELLYFISH_FSON_TYPE_U16,
    JELLYFISH_FSON_TYPE_U32,
    JELLYFISH_FSON_TYPE_U64,
    JELLYFISH_FSON_TYPE_F32,
    JELLYFISH_FSON_TYPE_F64,

    /* Literal number bases */
    JELLYFISH_FSON_TYPE_OCT,
    JELLYFISH_FSON_TYPE_HEX,
    JELLYFISH_FSON_TYPE_BIN,

    /* Strings and chars */
    JELLYFISH_FSON_TYPE_CHAR,
    JELLYFISH_FSON_TYPE_CSTR,

    /* Composite containers */
    JELLYFISH_FSON_TYPE_ARRAY,
    JELLYFISH_FSON_TYPE_OBJECT,

    /* Extended */
    JELLYFISH_FSON_TYPE_ENUM,
    JELLYFISH_FSON_TYPE_DATETIME,
    JELLYFISH_FSON_TYPE_DURATION
} fossil_ai_jellyfish_fson_type_t;

/* Capacity limits (tunable) */
enum {
    FOSSIL_JELLYFISH_FSON_MAX_ARRAY  = 32,
    FOSSIL_JELLYFISH_FSON_MAX_OBJECT = 32,
    FOSSIL_JELLYFISH_FSON_KEY_SIZE   = 32
};

typedef struct fossil_ai_jellyfish_fson_value fossil_ai_jellyfish_fson_value_t;

/* ---------------------------------------------------------------------------
 * Value Representation
 * --------------------------------------------------------------------------- */
struct fossil_ai_jellyfish_fson_value {
    fossil_ai_jellyfish_fson_type_t type;
    union {
        /* Scalars */
        int boolean;
        int8_t i8;
        int16_t i16;
        int32_t i32;
        int64_t i64;
        uint8_t u8;
        uint16_t u16;
        uint32_t u32;
        uint64_t u64;
        float f32;
        double f64;

        /* Encoded numbers (stored as raw unsigned) */
        uint64_t oct;
        uint64_t hex;
        uint64_t bin;

        /* Characters and strings */
        char character;
        char *cstr; /* heap-owned NUL string (optional) */

        /* Enum symbol */
        struct {
            char *symbol;          /* chosen symbol */
            const char **allowed;  /* optional allowed set */
            size_t allowed_count;
        } enum_val;

        /* Date/time (nanoseconds since epoch) */
        struct {
            int64_t epoch_ns;
        } datetime;

        /* Duration (nanoseconds) */
        struct {
            int64_t ns;
        } duration;

        /* Fixed-capacity array */
        struct {
            fossil_ai_jellyfish_fson_value_t *items[FOSSIL_JELLYFISH_FSON_MAX_ARRAY];
            size_t count;
        } array;

        /* Fixed-capacity object (key/value map) */
        struct {
            char keys[FOSSIL_JELLYFISH_FSON_MAX_OBJECT][FOSSIL_JELLYFISH_FSON_KEY_SIZE];
            fossil_ai_jellyfish_fson_value_t *values[FOSSIL_JELLYFISH_FSON_MAX_OBJECT];
            size_t count;
        } object;
    } u;
};

/**
 * @brief Block Attributes
 * Similar to commit metadata and trust heuristics.
 */
typedef struct {
    int immutable;
    int valid;
    float confidence;
    uint32_t usage_count;
    int pruned;
    int redacted;
    int deduplicated;
    int compressed;
    int expired;
    int trusted;
    int conflicted;
    int reserved;
} fossil_ai_jellyfish_block_attributes_t;

/**
 * @brief Block Timing Information
 */
typedef struct {
    uint64_t timestamp;       // Creation time (commit time)
    uint32_t delta_ms;        // Time since parent commit
    uint32_t duration_ms;     // Processing or IO duration
    uint64_t updated_at;
    uint64_t expires_at;
    uint64_t validated_at;
} fossil_ai_jellyfish_block_time_t;

/**
 * @brief Identification & Ancestry (Git-style DAG commit model)
 */
typedef struct {
    uint8_t commit_hash[FOSSIL_JELLYFISH_HASH_SIZE];       // Unique commit identifier
    uint8_t parent_hashes[4][FOSSIL_JELLYFISH_HASH_SIZE];  // Up to 4 parents (for merges)
    size_t parent_count;                                   // Number of parent commits
    uint8_t tree_hash[FOSSIL_JELLYFISH_HASH_SIZE];         // Tree-like content snapshot hash
    uint8_t author_id[FOSSIL_DEVICE_ID_SIZE];              // Author (device/user)
    uint8_t committer_id[FOSSIL_DEVICE_ID_SIZE];           // Committer (system or AI agent)
    uint8_t signature[FOSSIL_SIGNATURE_SIZE];              // Signature for integrity
    uint32_t signature_len;
    uint32_t commit_index;                                 // Local index in memory
    uint32_t branch_id;                                    // Logical branch index (for merges)
    char commit_message[256];                              // Human-readable reasoning summary
    int is_merge_commit;                                   // 1 if multi-parent
    int detached;                                          // 1 if not attached to mainline
    uint32_t reserved;
} fossil_ai_jellyfish_block_identity_t;

/**
 * @brief Classification / Semantic Relationships
 */
typedef struct {
    uint32_t derived_from_index;                           // Logical origin
    uint32_t cross_refs[FOSSIL_JELLYFISH_MAX_LINKS];       // Cross-branch references
    size_t cross_ref_count;
    uint32_t forward_refs[FOSSIL_JELLYFISH_MAX_LINKS];     // Future derivations
    size_t forward_ref_count;
    uint16_t reasoning_depth;
    uint16_t reserved;
    char classification_reason[128];
    char tags[FOSSIL_JELLYFISH_MAX_TAGS][32];
    float similarity_score;
    int is_hallucinated;
    int is_contradicted;

    /* FSON extension: arbitrary semantic metadata (object root) */
    fossil_ai_jellyfish_fson_value_t semantic_meta;           // Initialize to NULL; set to OBJECT for dynamic keys
} fossil_ai_jellyfish_block_classification_t;

/**
 * @brief Input/Output Core Payload
 */
typedef struct {
    char input[FOSSIL_JELLYFISH_INPUT_SIZE];
    char output[FOSSIL_JELLYFISH_OUTPUT_SIZE];
    size_t input_len;
    size_t output_len;
    char input_tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
    size_t input_token_count;
    char output_tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
    size_t output_token_count;
    int compressed;
    int redacted;
    int reserved;

    /* FSON extension: structured IO annotations (e.g., parse tree, embeddings refs) */
    fossil_ai_jellyfish_fson_value_t io_meta;                 // Root object or NULL
} fossil_ai_jellyfish_block_io_t;

/**
 * @brief Flexible Structured Object Notation (FSON) attachments
 * Allows arbitrary structured metadata (extended reasoning traces, metrics, lineage).
 */
typedef struct {
    fossil_ai_jellyfish_fson_value_t root;                    // Root object (OBJECT or NULL)
    fossil_ai_jellyfish_fson_value_t *attachments[FOSSIL_JELLYFISH_FSON_MAX_ARRAY];
    size_t attachment_count;
} fossil_ai_jellyfish_block_fson_t;

/**
 * @brief Complete Git-Chain Block (Commit)
 */
typedef struct {
    fossil_ai_jellyfish_block_io_t io;
    fossil_ai_jellyfish_block_identity_t identity;
    fossil_ai_jellyfish_block_time_t time;
    fossil_ai_jellyfish_block_attributes_t attributes;
    fossil_ai_jellyfish_commit_type_t block_type;
    fossil_ai_jellyfish_block_classification_t classify;
    fossil_ai_jellyfish_block_fson_t fson;                    // General-purpose extensible metadata
    fossil_ai_jellyfish_fson_value_t audit_meta;              // Per-block audit / validation record (OBJECT)
} fossil_ai_jellyfish_block_t;

/**
 * @brief Git-like Repository of Jellyfish Blocks
 */
typedef struct {
    fossil_ai_jellyfish_block_t commits[FOSSIL_JELLYFISH_MAX_MEM];
    size_t count;

    uint8_t repo_id[FOSSIL_DEVICE_ID_SIZE];      // Unique repository/device
    char default_branch[64];                     // Default branch name
    uint64_t created_at;
    uint64_t updated_at;

    // Branch & reference metadata
    struct {
        char name[64];
        uint8_t head_hash[FOSSIL_JELLYFISH_HASH_SIZE];
        fossil_ai_jellyfish_fson_value_t branch_meta;  // Branch-level dynamic metadata
    } branches[FOSSIL_JELLYFISH_MAX_BRANCHES];
    size_t branch_count;

    /* Repository-wide metadata (OBJECT root for global settings, stats cache, policies) */
    fossil_ai_jellyfish_fson_value_t repo_meta;
} fossil_ai_jellyfish_chain_t;

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
void fossil_ai_jellyfish_hash(const char *input, const char *output, uint8_t *hash_out);

/**
 * Initialize the jellyfish chain (Git-chain + FSON aware).
 *
 * Behavior:
 * - Resets all commit slots to a neutral (invalid) state without heap leaks.
 * - Initializes repository metadata container (repo_meta) as OBJECT for key/value AI policies.
 * - Sets timestamps (created_at, updated_at) using current wall-clock.
 * - Zeros branch descriptors and sets a default branch (e.g., "main") if empty.
 * - FSON substructures (audit_meta, semantic_meta, io_meta) are reset to NULL type.
 *
 * AI Context:
 * - Establishes a clean memory substrate for subsequent learning (INFER) commits.
 * - Ensures deterministic starting state so heuristic trust metrics begin at neutral baselines.
 *
 * Complexity:
 * - Time: O(C) where C = FOSSIL_JELLYFISH_MAX_MEM (fixed upper bound ⇒ effectively O(1) amortized).
 * - Space: O(1) additional; operates in-place.
 *
 * Thread-safety: Not thread-safe. Caller must externally synchronize.
 */
void fossil_ai_jellyfish_init(fossil_ai_jellyfish_chain_t *chain);

/**
 * Learn a new input-output pair (creates an INFER commit).
 *
 * Behavior:
 * - Tokenizes input/output into fixed token arrays for lightweight similarity metrics.
 * - Hashes input/output to produce commit_hash (content-addressable model).
 * - Sets block_type = JELLY_COMMIT_INFER and initializes confidence heuristically (e.g., mid/high).
 * - If capacity is full, may refuse insertion (caller can prune/compact then retry).
 *
 * AI Context:
 * - Represents a new reasoning fact / mapping the system can later validate, reinforce, or prune.
 * - Serves as a training-like memory append in a bounded, non-reallocating store.
 *
 * Complexity:
 * - Time: O(L + T) where L = length of input+output, T = token count (bounded ⇒ effectively O(1)).
 * - Space: O(1) incremental (fixed slot).
 */
void fossil_ai_jellyfish_learn(fossil_ai_jellyfish_chain_t *chain, const char *input, const char *output);

/**
 * Remove (logically) a block at index by marking attributes.valid = 0 (lazy deletion).
 * Physical compaction deferred to fossil_ai_jellyfish_chain_compact.
 *
 * AI Context:
 * - Enables forgetting of outdated or contradictory knowledge while preserving index locality
 *   until a maintenance pass consolidates the structure.
 *
 * Complexity:
 * - Time: O(1)
 * - Space: O(1)
 */
void fossil_ai_jellyfish_remove(fossil_ai_jellyfish_chain_t *chain, size_t index);

/**
 * Find a block by its hash (linear scan).
 *
 * AI Context:
 * - Supports verification, referencing, and DAG operations (parent lookups / merges).
 *
 * Complexity:
 * - Time: O(N) where N ≤ C (C fixed ⇒ practically O(1) bounded, but linear within active range).
 * - Space: O(1)
 */
fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_find(fossil_ai_jellyfish_chain_t *chain, const uint8_t *hash);

/**
 * Update a block's IO payload (if not immutable) and rehash content.
 *
 * Steps:
 * - Validates index and mutability (immutable blocks rejected).
 * - Replaces input/output, re-tokenizes, recomputes hash + updates updated_at.
 * - May reset some derived attributes (e.g., confidence decay partial reset).
 *
 * AI Context:
 * - Models correction / refinement akin to PATCH or REBASE of reasoning.
 *
 * Complexity:
 * - Time: O(L) (retokenization + hashing) with L bounded by fixed input/output sizes.
 * - Space: O(1)
 */
void fossil_ai_jellyfish_update(fossil_ai_jellyfish_chain_t *chain, size_t index, const char *input, const char *output);

/* ---------------------------- Persistence ---------------------------------- */

/**
 * Serialize chain to a binary file (fixed-structure dump).
 *
 * Complexity:
 * - Time: O(C) writes.
 * - Space: O(1) transient.
 *
 * AI Context:
 * - Enables checkpointing of evolving reasoning state for reproducibility / audit.
 */
int fossil_ai_jellyfish_save(const fossil_ai_jellyfish_chain_t *chain, const char *filepath);

/**
 * Load chain from binary snapshot (overwrites in-memory state).
 *
 * Complexity:
 * - Time: O(C) reads.
 * - Space: O(1)
 *
 * AI Context:
 * - Restores prior cognitive state enabling continuity across sessions.
 */
int fossil_ai_jellyfish_load(fossil_ai_jellyfish_chain_t *chain, const char *filepath);

/* ----------------------------- Maintenance --------------------------------- */

/**
 * Cleanup pass:
 * - Optionally reclaims transient fields, resets expired blocks, enforces invariants.
 *
 * Complexity: O(C)
 * AI Context: Maintains hygiene ensuring stale or malformed reasoning nodes don't pollute metrics.
 */
void fossil_ai_jellyfish_cleanup(fossil_ai_jellyfish_chain_t *chain);

/**
 * Audit pass:
 * - Scans blocks, validates structural + cryptographic integrity.
 * - Returns number of anomalies found.
 *
 * Complexity: O(C)
 * AI Context: Trust scaffolding—supports self-inspection (metacognition proxy).
 */
int  fossil_ai_jellyfish_audit(const fossil_ai_jellyfish_chain_t *chain);

/**
 * Prune:
 * - Removes (invalidates) blocks below min_confidence or expired.
 * - Returns count pruned.
 *
 * Complexity: O(C)
 * AI Context: Cognitive shaping—filters low-signal or decayed memories.
 */
int  fossil_ai_jellyfish_prune(fossil_ai_jellyfish_chain_t *chain, float min_confidence);

/* ------------------------------ Reasoning ---------------------------------- */

/**
 * Reason:
 * - Performs similarity / direct match search over inputs.
 * - Returns best output string or "Unknown".
 *
 * Complexity: O(N * M) where N = active blocks, M = cost of token similarity (bounded).
 * AI Context: Lightweight retrieval-based inference (non-generative).
 */
const char *fossil_ai_jellyfish_reason(fossil_ai_jellyfish_chain_t *chain, const char *input);

/**
 * Verbose reasoning:
 * - Provides output, confidence score, and pointer to matched block.
 *
 * Complexity: Same as fossil_ai_jellyfish_reason.
 * AI Context: Introspection hook exposing internal match quality.
 */
bool fossil_ai_jellyfish_reason_verbose(const fossil_ai_jellyfish_chain_t *chain, const char *input,
                                     char *out_output, float *out_confidence,
                                     const fossil_ai_jellyfish_block_t **out_block);

/**
 * Best approximate match (semantic / token overlap heuristic).
 *
 * Complexity: O(N * M)
 * AI Context: Supports context expansion / chaining.
 */
const fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_best_match(const fossil_ai_jellyfish_chain_t *chain,
                                                            const char *input);

/* ------------------------------- Diagnostics ------------------------------- */

/**
 * Dump chain to stdout (debug).
 * Complexity: O(C)
 */
void fossil_ai_jellyfish_dump(const fossil_ai_jellyfish_chain_t *chain);

/**
 * Reflect:
 * - Summarizes distribution (confidence, age, trust) for self-assessment.
 * Complexity: O(C)
 */
void fossil_ai_jellyfish_reflect(const fossil_ai_jellyfish_chain_t *chain);

/**
 * Validation report per block.
 * Complexity: O(C)
 */
void fossil_ai_jellyfish_validation_report(const fossil_ai_jellyfish_chain_t *chain);

/**
 * Verify entire chain (hash + link integrity).
 * Complexity: O(C)
 */
bool fossil_ai_jellyfish_verify_chain(const fossil_ai_jellyfish_chain_t *chain);

/**
 * Verify single block (hash recomputation, signature, structural).
 * Complexity: O(1)
 */
bool fossil_ai_jellyfish_verify_block(const fossil_ai_jellyfish_block_t *block);

/**
 * Chain trust aggregate (weighted mean over valid blocks).
 * Complexity: O(C)
 */
float fossil_ai_jellyfish_chain_trust_score(const fossil_ai_jellyfish_chain_t *chain);

/**
 * Compute repository fingerprint (aggregate hash).
 * Complexity: O(C)
 */
void fossil_ai_jellyfish_chain_fingerprint(const fossil_ai_jellyfish_chain_t *chain, uint8_t *out_hash);

/**
 * Collect stats arrays (valid counts, averages, ratios).
 * Complexity: O(C)
 */
void fossil_ai_jellyfish_chain_stats(const fossil_ai_jellyfish_chain_t *chain,
                                  size_t out_valid_count[5],
                                  float  out_avg_confidence[5],
                                  float  out_immutable_ratio[5]);

/**
 * Compare two chains (block-by-block hash / semantic delta).
 * Returns differing count.
 * Complexity: O(C)
 */
int fossil_ai_jellyfish_compare_chains(const fossil_ai_jellyfish_chain_t *a,
                                    const fossil_ai_jellyfish_chain_t *b);

/**
 * Compute age (now - timestamp).
 * Complexity: O(1)
 */
uint64_t fossil_ai_jellyfish_block_age(const fossil_ai_jellyfish_block_t *block, uint64_t now);

/**
 * Produce concise diagnostic string for a block.
 * Complexity: O(1)
 */
void fossil_ai_jellyfish_block_explain(const fossil_ai_jellyfish_block_t *block, char *out, size_t size);

/* ----------------------------- Optimization -------------------------------- */

/**
 * Decay confidence for all blocks: confidence *= (1 - decay_rate).
 * Complexity: O(C)
 * AI Context: Simulates memory fading to privilege recent reinforcement.
 */
void fossil_ai_jellyfish_decay_confidence(fossil_ai_jellyfish_chain_t *chain, float decay_rate);

/**
 * Trim chain to max_blocks by heuristic (e.g., confidence or recency).
 * Complexity: O(C log C) if sorting; O(C) if linear selection.
 */
int  fossil_ai_jellyfish_trim(fossil_ai_jellyfish_chain_t *chain, size_t max_blocks);

/**
 * Compact:
 * - Physically packs valid blocks forward, preserving relative order.
 * Complexity: O(C)
 */
int  fossil_ai_jellyfish_chain_compact(fossil_ai_jellyfish_chain_t *chain);

/**
 * Deduplicate identical input/output pairs (retaining higher-confidence or earlier).
 * Complexity: O(C^2) naive; could be O(C log C) if hashed (implementation-dependent).
 */
int  fossil_ai_jellyfish_deduplicate_chain(fossil_ai_jellyfish_chain_t *chain);

/**
 * Compress chain:
 * - Whitespace trimming, optional shortening, marks compressed flag.
 * Complexity: O(C * L) with L bounded by IO field size.
 */
int  fossil_ai_jellyfish_compress_chain(fossil_ai_jellyfish_chain_t *chain);

/* ------------------------------- Hash / Search ------------------------------ */

/**
 * Deterministic hash of input+output (content addressing).
 * Complexity: O(L)
 */
void fossil_ai_jellyfish_hash(const char *input, const char *output, uint8_t *hash_out);

/**
 * Select highest-confidence valid block.
 * Complexity: O(C)
 */
const fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_best_memory(const fossil_ai_jellyfish_chain_t *chain);

/**
 * Knowledge coverage: normalized count/quality ratio.
 * Complexity: O(C)
 */
float fossil_ai_jellyfish_knowledge_coverage(const fossil_ai_jellyfish_chain_t *chain);

/**
 * Detect conflict (same input with different output).
 * Complexity: O(C)
 */
int   fossil_ai_jellyfish_detect_conflict(const fossil_ai_jellyfish_chain_t *chain,
                                       const char *input, const char *output);

/**
 * Hash lookup (read-only).
 * Complexity: O(N) linear.
 */
const fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_find_by_hash(const fossil_ai_jellyfish_chain_t *chain,
                                                              const uint8_t *hash);

/**
 * Direct index accessor.
 * Complexity: O(1)
 */
fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_get(fossil_ai_jellyfish_chain_t *chain, size_t index);

/* --------------------------- Block Attribute Ops --------------------------- */

/**
 * Mark immutable (locks future mutation).
 * Complexity: O(1)
 */
void fossil_ai_jellyfish_mark_immutable(fossil_ai_jellyfish_block_t *block);

/**
 * Redact sensitive IO (masking, zeroing).
 * Complexity: O(L)
 */
int  fossil_ai_jellyfish_redact_block(fossil_ai_jellyfish_block_t *block);

/**
 * Set commit message (bounded copy).
 * Complexity: O(M) with M bounded.
 */
int  fossil_ai_jellyfish_block_set_message(fossil_ai_jellyfish_block_t *block, const char *message);

/**
 * Change block type (e.g., promote INFER → VALIDATE).
 * Complexity: O(1)
 */
int  fossil_ai_jellyfish_block_set_type(fossil_ai_jellyfish_block_t *block,
                                     fossil_ai_jellyfish_commit_type_t type);

/* --------------------------- Classification Helpers ------------------------ */

/**
 * Append tag if capacity allows.
 * Complexity: O(T_tag) (bounded).
 */
int fossil_ai_jellyfish_block_add_tag(fossil_ai_jellyfish_block_t *block, const char *tag);

/**
 * Set human-readable classification reason.
 * Complexity: O(R) bounded.
 */
int fossil_ai_jellyfish_block_set_reason(fossil_ai_jellyfish_block_t *block, const char *reason);

/**
 * Update similarity score (float).
 * Complexity: O(1)
 */
int fossil_ai_jellyfish_block_set_similarity(fossil_ai_jellyfish_block_t *block, float similarity);

/**
 * Link forward reference (derivation chain).
 * Complexity: O(1)
 */
int fossil_ai_jellyfish_block_link_forward(fossil_ai_jellyfish_block_t *block, uint32_t target_index);

/**
 * Link cross reference (semantic lateral link).
 * Complexity: O(1)
 */
int fossil_ai_jellyfish_block_link_cross(fossil_ai_jellyfish_block_t *block, uint32_t target_index);

/* ------------------------------ Git-Chain Ops ------------------------------ */

/**
 * Add a generic commit with explicit parents and type.
 *
 * Behavior:
 * - Copies up to 4 parent hashes to parent list.
 * - Computes commit hash from IO + parent metadata + type.
 * - Optionally sets commit_message if provided.
 *
 * AI Context:
 * - Enables modeling of reasoning lineage merges, experimental forks, trusted validations.
 *
 * Complexity:
 * - Time: O(P + L) where P = parent_count (≤4), L = IO length (bounded).
 * - Space: O(1)
 */
fossil_ai_jellyfish_block_t *fossil_ai_jellyfish_add_commit(
    fossil_ai_jellyfish_chain_t *chain,
    const char *input,
    const char *output,
    fossil_ai_jellyfish_commit_type_t type,
    const uint8_t parent_hashes[][FOSSIL_JELLYFISH_HASH_SIZE],
    size_t parent_count,
    const char *message);

/**
 * Set parent hashes on an existing block.
 * Complexity: O(P)
 */
int fossil_ai_jellyfish_commit_set_parents(fossil_ai_jellyfish_block_t *block,
                                        const uint8_t parent_hashes[][FOSSIL_JELLYFISH_HASH_SIZE],
                                        size_t parent_count);

/**
 * Return human-readable commit type string.
 * Complexity: O(1)
 */
const char *fossil_ai_jellyfish_commit_type_name(fossil_ai_jellyfish_commit_type_t type);

/* Branch management */

/**
 * Create branch if capacity available.
 * Complexity: O(B) scan (B = branches, small fixed).
 */
int fossil_ai_jellyfish_branch_create(fossil_ai_jellyfish_chain_t *chain, const char *name);

/**
 * Checkout branch (updates active branch meta).
 * Complexity: O(B)
 */
int fossil_ai_jellyfish_branch_checkout(fossil_ai_jellyfish_chain_t *chain, const char *name);

/**
 * Find branch index by name.
 * Complexity: O(B)
 */
int fossil_ai_jellyfish_branch_find(const fossil_ai_jellyfish_chain_t *chain, const char *name);

/**
 * Retrieve active branch name.
 * Complexity: O(1)
 */
const char *fossil_ai_jellyfish_branch_active(const fossil_ai_jellyfish_chain_t *chain);

/**
 * Update head hash of active branch.
 * Complexity: O(1)
 */
int fossil_ai_jellyfish_branch_head_update(fossil_ai_jellyfish_chain_t *chain, const uint8_t *new_head_hash);

/* Merge / rebase / cherry-pick */

/**
 * Merge source into target, creates MERGE commit with dual parents.
 * Complexity: O(C) for resolution heuristics (if conflict scan); else O(1).
 */
int fossil_ai_jellyfish_merge(fossil_ai_jellyfish_chain_t *chain,
                           const char *source_branch,
                           const char *target_branch,
                           const char *message);

/**
 * Rebase branch onto another (rewrites lineage).
 * Complexity: O(K) where K = number of commits rebased (≤ C).
 */
int fossil_ai_jellyfish_rebase(fossil_ai_jellyfish_chain_t *chain,
                            const char *branch,
                            const char *onto_branch);

/**
 * Cherry-pick single commit by hash onto current branch.
 * Complexity: O(C) (find + duplicate).
 */
int fossil_ai_jellyfish_cherry_pick(fossil_ai_jellyfish_chain_t *chain, const uint8_t *commit_hash);

/* Tagging */

/**
 * Add tag to block (delegates to classification tags).
 * Complexity: O(1)
 */
int fossil_ai_jellyfish_tag_block(fossil_ai_jellyfish_block_t *block, const char *tag);

/* ------------------------------ FSON Utilities ----------------------------- */

/**
 * Initialize FSON value to NULL type.
 * Complexity: O(1)
 */
void fossil_ai_jellyfish_fson_init(fossil_ai_jellyfish_fson_value_t *v);

/**
 * Reset (recursively frees owned dynamic strings/children if needed).
 * Complexity: O(S) where S = subtree size.
 */
void fossil_ai_jellyfish_fson_reset(fossil_ai_jellyfish_fson_value_t *v);

/**
 * Set C-string (duplicates / owns).
 * Complexity: O(len)
 */
int  fossil_ai_jellyfish_fson_set_cstr(fossil_ai_jellyfish_fson_value_t *v, const char *s);

/**
 * Set 64-bit integer.
 * Complexity: O(1)
 */
int  fossil_ai_jellyfish_fson_set_i64(fossil_ai_jellyfish_fson_value_t *v, int64_t val);

/**
 * Set double.
 * Complexity: O(1)
 */
int  fossil_ai_jellyfish_fson_set_f64(fossil_ai_jellyfish_fson_value_t *v, double val);

/**
 * Set boolean.
 * Complexity: O(1)
 */
int  fossil_ai_jellyfish_fson_set_bool(fossil_ai_jellyfish_fson_value_t *v, int val);

/**
 * Make object (initial empty map).
 * Complexity: O(1)
 */
int  fossil_ai_jellyfish_fson_make_object(fossil_ai_jellyfish_fson_value_t *v);

/**
 * Make array.
 * Complexity: O(1)
 */
int  fossil_ai_jellyfish_fson_make_array(fossil_ai_jellyfish_fson_value_t *v);

/**
 * Put key/value in object (fails if full).
 * Complexity: O(1) (linear scan bounded by capacity).
 */
int  fossil_ai_jellyfish_fson_object_put(fossil_ai_jellyfish_fson_value_t *obj,
                                      const char *key,
                                      fossil_ai_jellyfish_fson_value_t *value);

/**
 * Get value by key.
 * Complexity: O(K) where K ≤ FOSSIL_JELLYFISH_FSON_MAX_OBJECT (bounded).
 */
fossil_ai_jellyfish_fson_value_t *fossil_ai_jellyfish_fson_object_get(const fossil_ai_jellyfish_fson_value_t *obj,
                                                                const char *key);

/**
 * Push value to array.
 * Complexity: O(1)
 */
int  fossil_ai_jellyfish_fson_array_push(fossil_ai_jellyfish_fson_value_t *arr,
                                      fossil_ai_jellyfish_fson_value_t *value);

/**
 * Get array element.
 * Complexity: O(1)
 */
fossil_ai_jellyfish_fson_value_t *fossil_ai_jellyfish_fson_array_get(const fossil_ai_jellyfish_fson_value_t *arr,
                                                               size_t index);

/**
 * Length of array.
 * Complexity: O(1)
 */
size_t fossil_ai_jellyfish_fson_array_length(const fossil_ai_jellyfish_fson_value_t *arr);

/**
 * Deep copy subtree.
 * Complexity: O(S) where S = number of nodes.
 */
int  fossil_ai_jellyfish_fson_copy(const fossil_ai_jellyfish_fson_value_t *src,
                                fossil_ai_jellyfish_fson_value_t *dst);

/**
 * Free subtree (recursively).
 * Complexity: O(S)
 */
void fossil_ai_jellyfish_fson_free(fossil_ai_jellyfish_fson_value_t *v);

/* -------------------------- Block FSON Attachments ------------------------- */

/**
 * Set semantic key/value inside block.classify.semantic_meta (OBJECT).
 * Complexity: O(1) per insertion (bounded).
 */
int fossil_ai_jellyfish_block_set_semantic_kv(fossil_ai_jellyfish_block_t *block,
                                           const char *key,
                                           fossil_ai_jellyfish_fson_value_t *value);

/**
 * Add auxiliary attachment to block.fson.attachments.
 * Complexity: O(1)
 */
int fossil_ai_jellyfish_block_add_attachment(fossil_ai_jellyfish_block_t *block,
                                          fossil_ai_jellyfish_fson_value_t *attachment);

/**
 * Set audit metadata object.
 * Complexity: O(1)
 */
int fossil_ai_jellyfish_block_set_audit_meta(fossil_ai_jellyfish_block_t *block,
                                          fossil_ai_jellyfish_fson_value_t *meta);

/* --------------------------- Chain-level FSON Meta ------------------------- */

/**
 * Insert repository-level metadata key/value (policies, stats).
 * Complexity: O(1) (bounded object size).
 */
int fossil_ai_jellyfish_repo_meta_put(fossil_ai_jellyfish_chain_t *chain,
                                   const char *key,
                                   fossil_ai_jellyfish_fson_value_t *value);

/* ---------------------------- Cryptographic Ops --------------------------- */

/**
 * Sign block (e.g., ED25519) over canonical serialized subset.
 * Complexity: O(1) (constant-size signing).
 */
int  fossil_ai_jellyfish_block_sign(fossil_ai_jellyfish_block_t *block, const uint8_t *priv_key);

/**
 * Verify signature.
 * Complexity: O(1)
 */
bool fossil_ai_jellyfish_block_verify_signature(const fossil_ai_jellyfish_block_t *block,
                                             const uint8_t *pub_key);

/* ------------------------------ Tokenization ------------------------------- */

/**
 * Tokenize input into lowercase alphanumeric tokens.
 * Complexity: O(L) where L = input length (bounded by buffer).
 */
size_t fossil_ai_jellyfish_tokenize(const char *input,
                                 char tokens[][FOSSIL_JELLYFISH_TOKEN_SIZE],
                                 size_t max_tokens);

/* ------------------------------- Cloning ----------------------------------- */

/**
 * Deep clone chain (including FSON deep copies).
 * Complexity: O(C + S_total) where S_total = sum of FSON subtree sizes.
 */
int fossil_ai_jellyfish_clone_chain(const fossil_ai_jellyfish_chain_t *src,
                                 fossil_ai_jellyfish_chain_t *dst);

#ifdef __cplusplus
}
#include <stdexcept>
#include <cstdint>
#include <vector>
#include <array>
#include <string>

namespace fossil {

namespace ai {

    /**
     * @class Jellyfish
     * @brief C++ RAII wrapper over the C fossil_ai_jellyfish_* API.
     *
     * Responsibilities:
     * - Owns a fossil_ai_jellyfish_chain_t instance.
     * - Provides type-safe, exception-free (no-throw) thin forwarding methods.
     * - Supplies small utility helpers (parent vector marshalling, RAII FSON).
     *
     * Lifetime:
     * - Default constructor initializes the chain (zeroed & ready).
     * - Copy constructor / assignment perform deep clone (including FSON subtrees).
     * - Move operations shallowly move underlying POD (safe because struct has no owning heap
     *   pointers beyond what C layer manages; if that changes, move logic must be revisited).
     *
     * Thread-safety: Not internally synchronized; external synchronization required.
     */
    class Jellyfish {
    public:
        /**
         * @brief Construct and initialize an empty chain.
         */
        Jellyfish() { ::fossil_ai_jellyfish_init(&chain_); }

        /**
         * @brief Destructor (currently no explicit teardown needed; placeholder).
         */
        ~Jellyfish() { /* optional: cleanup if implementation allocs */ }

        /**
         * @brief Deep copy from another Jellyfish (clones chain & FSON).
         */
        Jellyfish(const Jellyfish& other) { ::fossil_ai_jellyfish_clone_chain(&other.chain_, &chain_); }

        /**
         * @brief Copy-assign via deep clone. Self-safe.
         * @return *this
         */
        Jellyfish& operator=(const Jellyfish& other) {
            if (this != &other) {
                ::fossil_ai_jellyfish_clone_chain(&other.chain_, &chain_);
            }
            return *this;
        }

        /**
         * @brief Move construct (bitwise move of POD chain_).
         */
        Jellyfish(Jellyfish&& other) noexcept { chain_ = other.chain_; }

        /**
         * @brief Move assign (bitwise move of POD chain_). Self-safe.
         * @return *this
         */
        Jellyfish& operator=(Jellyfish&& other) noexcept {
            if (this != &other) chain_ = other.chain_;
            return *this;
        }

        // ---- Basic core ----

        /**
         * @brief Static helper: compute deterministic hash for input/output pair.
         */
        static void hash(const char* input, const char* output, uint8_t* hash_out) {
            ::fossil_ai_jellyfish_hash(input, output, hash_out);
        }

        /**
         * @brief Reinitialize the internal chain (destructive reset).
         */
        void init() { ::fossil_ai_jellyfish_init(&chain_); }

        /**
         * @brief Append a learning (INFER) commit with given IO pair.
         */
        void learn(const char* input, const char* output) {
            ::fossil_ai_jellyfish_learn(&chain_, input, output);
        }

        /**
         * @brief Logically remove (invalidate) block by index.
         */
        void remove(size_t index) { ::fossil_ai_jellyfish_remove(&chain_, index); }

        /**
         * @brief Find mutable block by hash (linear scan).
         * @return pointer or nullptr.
         */
        fossil_ai_jellyfish_block_t* find(const uint8_t* hash) {
            return ::fossil_ai_jellyfish_find(&chain_, hash);
        }

        /**
         * @brief Get mutable block by index.
         */
        fossil_ai_jellyfish_block_t* get(size_t index) {
            return ::fossil_ai_jellyfish_get(&chain_, index);
        }

        /**
         * @brief Update block IO and rehash.
         */
        void update(size_t index, const char* input, const char* output) {
            ::fossil_ai_jellyfish_update(&chain_, index, input, output);
        }

        /**
         * @brief Persist chain to binary file.
         * @return 0 on success.
         */
        int save(const char* filepath) const { return ::fossil_ai_jellyfish_save(&chain_, filepath); }

        /**
         * @brief Load chain from binary file (overwrites current state).
         * @return 0 on success.
         */
        int load(const char* filepath) { return ::fossil_ai_jellyfish_load(&chain_, filepath); }

        // ---- Maintenance / metrics ----

        /**
         * @brief Perform hygiene cleanup pass.
         */
        void cleanup() { ::fossil_ai_jellyfish_cleanup(&chain_); }

        /**
         * @brief Run audit returning anomaly count.
         */
        int audit() const { return ::fossil_ai_jellyfish_audit(&chain_); }

        /**
         * @brief Prune low-confidence / expired blocks.
         * @param min_confidence threshold.
         */
        int prune(float min_confidence) { return ::fossil_ai_jellyfish_prune(&chain_, min_confidence); }

        // ---- Reasoning ----

        /**
         * @brief Retrieve best output for input (heuristic similarity).
         * @return output or "Unknown".
         */
        const char* reason(const char* input) { return ::fossil_ai_jellyfish_reason(&chain_, input); }

        /**
         * @brief Verbose reasoning (output + confidence + block reference).
         * @return true if match found.
         */
        bool reason_verbose(const char* input, char* out_output, float* out_confidence,
                            const fossil_ai_jellyfish_block_t** out_block) const {
            return ::fossil_ai_jellyfish_reason_verbose(&chain_, input, out_output, out_confidence, out_block);
        }

        /**
         * @brief Get pointer to best approximate matching block.
         */
        const fossil_ai_jellyfish_block_t* best_match(const char* input) const {
            return ::fossil_ai_jellyfish_best_match(&chain_, input);
        }

        // ---- Diagnostics ----

        /**
         * @brief Debug dump to stdout.
         */
        void dump() const { ::fossil_ai_jellyfish_dump(&chain_); }

        /**
         * @brief Print reflective summary stats.
         */
        void reflect() const { ::fossil_ai_jellyfish_reflect(&chain_); }

        /**
         * @brief Emit validation report to stdout.
         */
        void validation_report() const { ::fossil_ai_jellyfish_validation_report(&chain_); }

        /**
         * @brief Verify chain integrity (hash links).
         */
        bool verify_chain() const { return ::fossil_ai_jellyfish_verify_chain(&chain_); }

        /**
         * @brief Verify single block integrity.
         */
        static bool verify_block(const fossil_ai_jellyfish_block_t* block) {
            return ::fossil_ai_jellyfish_verify_block(block);
        }

        /**
         * @brief Aggregate trust metric for chain.
         */
        float chain_trust_score() const { return ::fossil_ai_jellyfish_chain_trust_score(&chain_); }

        /**
         * @brief Compute repository-wide fingerprint hash.
         */
        void chain_fingerprint(uint8_t* out_hash) const {
            ::fossil_ai_jellyfish_chain_fingerprint(&chain_, out_hash);
        }

        /**
         * @brief Collect categorized stats arrays.
         */
        void chain_stats(size_t out_valid_count[5], float out_avg_confidence[5],
                         float out_immutable_ratio[5]) const {
            ::fossil_ai_jellyfish_chain_stats(&chain_, out_valid_count, out_avg_confidence, out_immutable_ratio);
        }

        /**
         * @brief Compare with another chain instance.
         * @return differing block count.
         */
        int compare_chains(const Jellyfish& other) const {
            return ::fossil_ai_jellyfish_compare_chains(&chain_, &other.chain_);
        }

        // ---- Optimization ----

        /**
         * @brief Apply exponential decay to all confidences.
         */
        void decay_confidence(float decay_rate) {
            ::fossil_ai_jellyfish_decay_confidence(&chain_, decay_rate);
        }

        /**
         * @brief Trim to at most max_blocks (heuristic).
         */
        int trim(size_t max_blocks) { return ::fossil_ai_jellyfish_trim(&chain_, max_blocks); }

        /**
         * @brief Compact invalidated gaps.
         */
        int chain_compact() { return ::fossil_ai_jellyfish_chain_compact(&chain_); }

        /**
         * @brief Deduplicate equivalent IO pairs.
         */
        int deduplicate_chain() { return ::fossil_ai_jellyfish_deduplicate_chain(&chain_); }

        /**
         * @brief Compress (lightweight text normalization).
         */
        int compress_chain() { return ::fossil_ai_jellyfish_compress_chain(&chain_); }

        // ---- Hash / search helpers ----

        /**
         * @brief Select highest-confidence valid block.
         */
        const fossil_ai_jellyfish_block_t* best_memory() const {
            return ::fossil_ai_jellyfish_best_memory(&chain_);
        }

        /**
         * @brief Approximate knowledge coverage metric.
         */
        float knowledge_coverage() const {
            return ::fossil_ai_jellyfish_knowledge_coverage(&chain_);
        }

        /**
         * @brief Detect conflict (same input, differing output).
         * @return count of conflicts.
         */
        int detect_conflict(const char* input, const char* output) const {
            return ::fossil_ai_jellyfish_detect_conflict(&chain_, input, output);
        }

        /**
         * @brief Read-only hash lookup.
         */
        const fossil_ai_jellyfish_block_t* find_by_hash(const uint8_t* hash) const {
            return ::fossil_ai_jellyfish_find_by_hash(&chain_, hash);
        }

        // ---- Block attribute / classification ops ----

        /**
         * @brief Mark block immutable.
         */
        static void mark_immutable(fossil_ai_jellyfish_block_t* block) {
            ::fossil_ai_jellyfish_mark_immutable(block);
        }

        /**
         * @brief Redact sensitive IO fields.
         */
        static int redact_block(fossil_ai_jellyfish_block_t* block) {
            return ::fossil_ai_jellyfish_redact_block(block);
        }

        /**
         * @brief Set commit message text.
         */
        static int block_set_message(fossil_ai_jellyfish_block_t* block, const char* msg) {
            return ::fossil_ai_jellyfish_block_set_message(block, msg);
        }

        /**
         * @brief Change block commit type.
         */
        static int block_set_type(fossil_ai_jellyfish_block_t* block, fossil_ai_jellyfish_commit_type_t type) {
            return ::fossil_ai_jellyfish_block_set_type(block, type);
        }

        /**
         * @brief Append tag to block classification.
         */
        static int block_add_tag(fossil_ai_jellyfish_block_t* block, const char* tag) {
            return ::fossil_ai_jellyfish_block_add_tag(block, tag);
        }

        /**
         * @brief Set classification reason string.
         */
        static int block_set_reason(fossil_ai_jellyfish_block_t* block, const char* reason) {
            return ::fossil_ai_jellyfish_block_set_reason(block, reason);
        }

        /**
         * @brief Update similarity score.
         */
        static int block_set_similarity(fossil_ai_jellyfish_block_t* block, float sim) {
            return ::fossil_ai_jellyfish_block_set_similarity(block, sim);
        }

        /**
         * @brief Link forward reference index.
         */
        static int block_link_forward(fossil_ai_jellyfish_block_t* block, uint32_t idx) {
            return ::fossil_ai_jellyfish_block_link_forward(block, idx);
        }

        /**
         * @brief Link cross reference index.
         */
        static int block_link_cross(fossil_ai_jellyfish_block_t* block, uint32_t idx) {
            return ::fossil_ai_jellyfish_block_link_cross(block, idx);
        }

        /**
         * @brief Add tag alias (delegates to classification).
         */
        static int tag_block(fossil_ai_jellyfish_block_t* block, const char* tag) {
            return ::fossil_ai_jellyfish_tag_block(block, tag);
        }

        // ---- Git-chain style commit ops ----

        /**
         * @brief Add generic commit with explicit parents.
         * @param parents vector (max 4 used).
         * @return pointer to new block or nullptr.
         */
        fossil_ai_jellyfish_block_t* add_commit(const char* input,
                                                const char* output,
                                                fossil_ai_jellyfish_commit_type_t type,
                                                const std::vector<std::array<uint8_t, FOSSIL_JELLYFISH_HASH_SIZE>>& parents,
                                                const char* message) {
            uint8_t parent_buf[4][FOSSIL_JELLYFISH_HASH_SIZE] = {{0}};
            size_t pc = parents.size() > 4 ? 4 : parents.size();
            for (size_t i = 0; i < pc; ++i)
                memcpy(parent_buf[i], parents[i].data(), FOSSIL_JELLYFISH_HASH_SIZE);
            return ::fossil_ai_jellyfish_add_commit(&chain_, input, output, type, parent_buf, pc, message);
        }

        /**
         * @brief Set parents on an existing block.
         */
        static int commit_set_parents(fossil_ai_jellyfish_block_t* block,
                                      const std::vector<std::array<uint8_t, FOSSIL_JELLYFISH_HASH_SIZE>>& parents) {
            uint8_t parent_buf[4][FOSSIL_JELLYFISH_HASH_SIZE] = {{0}};
            size_t pc = parents.size() > 4 ? 4 : parents.size();
            for (size_t i = 0; i < pc; ++i)
                memcpy(parent_buf[i], parents[i].data(), FOSSIL_JELLYFISH_HASH_SIZE);
            return ::fossil_ai_jellyfish_commit_set_parents(block, parent_buf, pc);
        }

        /**
         * @brief Human-readable commit type name.
         */
        static const char* commit_type_name(fossil_ai_jellyfish_commit_type_t type) {
            return ::fossil_ai_jellyfish_commit_type_name(type);
        }

        // ---- Branch management ----

        /**
         * @brief Create new branch.
         */
        int branch_create(const char* name) { return ::fossil_ai_jellyfish_branch_create(&chain_, name); }

        /**
         * @brief Checkout existing branch.
         */
        int branch_checkout(const char* name) { return ::fossil_ai_jellyfish_branch_checkout(&chain_, name); }

        /**
         * @brief Find branch index by name.
         */
        int branch_find(const char* name) const { return ::fossil_ai_jellyfish_branch_find(&chain_, name); }

        /**
         * @brief Active branch name (or nullptr).
         */
        const char* branch_active() const { return ::fossil_ai_jellyfish_branch_active(&chain_); }

        /**
         * @brief Update HEAD hash of active branch.
         */
        int branch_head_update(const uint8_t* new_head) {
            return ::fossil_ai_jellyfish_branch_head_update(&chain_, new_head);
        }

        // ---- Merge / rebase / cherry-pick ----

        /**
         * @brief Merge source branch into target branch.
         */
        int merge(const char* source_branch, const char* target_branch, const char* message) {
            return ::fossil_ai_jellyfish_merge(&chain_, source_branch, target_branch, message);
        }

        /**
         * @brief Rebase branch onto another.
         */
        int rebase(const char* branch, const char* onto) {
            return ::fossil_ai_jellyfish_rebase(&chain_, branch, onto);
        }

        /**
         * @brief Cherry-pick commit onto current branch.
         */
        int cherry_pick(const uint8_t* commit_hash) {
            return ::fossil_ai_jellyfish_cherry_pick(&chain_, commit_hash);
        }

        // ---- FSON helper RAII wrapper ----
        /**
         * @class FsonValue
         * @brief RAII-managed fossil_ai_jellyfish_fson_value_t.
         *
         * Copy: deep copy. Move: transfer ownership by struct copy + nulling source.
         * Provides direct wrappers for primitive mutations and object/array operations.
         */
        class FsonValue {
        public:
            /**
             * @brief Construct NULL FSON value.
             */
            FsonValue() { ::fossil_ai_jellyfish_fson_init(&v_); }

            /**
             * @brief Destructor (recursively frees subtree).
             */
            ~FsonValue() { ::fossil_ai_jellyfish_fson_free(&v_); }

            /**
             * @brief Deep copy constructor.
             */
            FsonValue(const FsonValue& other) {
                ::fossil_ai_jellyfish_fson_init(&v_);
                ::fossil_ai_jellyfish_fson_copy(&other.v_, &v_);
            }

            /**
             * @brief Deep copy assignment.
             */
            FsonValue& operator=(const FsonValue& other) {
                if (this != &other) {
                    ::fossil_ai_jellyfish_fson_free(&v_);
                    ::fossil_ai_jellyfish_fson_init(&v_);
                    ::fossil_ai_jellyfish_fson_copy(&other.v_, &v_);
                }
                return *this;
            }

            /**
             * @brief Move constructor (steals internal union state).
             */
            FsonValue(FsonValue&& other) noexcept { v_ = other.v_; other.v_.type = JELLYFISH_FSON_TYPE_NULL; }

            /**
             * @brief Move assignment (frees old, takes new).
             */
            FsonValue& operator=(FsonValue&& other) noexcept {
                if (this != &other) {
                    ::fossil_ai_jellyfish_fson_free(&v_);
                    v_ = other.v_;
                    other.v_.type = JELLYFISH_FSON_TYPE_NULL;
                }
                return *this;
            }

            /**
             * @brief Set value to owned C-string.
             */
            int set_cstr(const char* s) { return ::fossil_ai_jellyfish_fson_set_cstr(&v_, s); }

            /**
             * @brief Set 64-bit integer scalar.
             */
            int set_i64(int64_t x) { return ::fossil_ai_jellyfish_fson_set_i64(&v_, x); }

            /**
             * @brief Set double scalar.
             */
            int set_f64(double d) { return ::fossil_ai_jellyfish_fson_set_f64(&v_, d); }

            /**
             * @brief Set boolean scalar.
             */
            int set_bool(int b) { return ::fossil_ai_jellyfish_fson_set_bool(&v_, b); }

            /**
             * @brief Convert to object container.
             */
            int make_object() { return ::fossil_ai_jellyfish_fson_make_object(&v_); }

            /**
             * @brief Convert to array container.
             */
            int make_array() { return ::fossil_ai_jellyfish_fson_make_array(&v_); }

            /**
             * @brief Put key/value into object (child stored by pointer).
             */
            int object_put(const char* key, FsonValue& child) {
                return ::fossil_ai_jellyfish_fson_object_put(&v_, key, &child.v_);
            }

            /**
             * @brief Get child by key (non-owning).
             */
            FsonValue* object_get(const char* key) {
                auto* p = ::fossil_ai_jellyfish_fson_object_get(&v_, key);
                return reinterpret_cast<FsonValue*>(p);
            }

            /**
             * @brief Append child to array.
             */
            int array_push(FsonValue& child) {
                return ::fossil_ai_jellyfish_fson_array_push(&v_, &child.v_);
            }

            /**
             * @brief Get array element pointer.
             */
            FsonValue* array_get(size_t idx) {
                auto* p = ::fossil_ai_jellyfish_fson_array_get(&v_, idx);
                return reinterpret_cast<FsonValue*>(p);
            }

            /**
             * @brief Current array length.
             */
            size_t array_length() const { return ::fossil_ai_jellyfish_fson_array_length(&v_); }

            /**
             * @brief Access native pointer (mutable).
             */
            fossil_ai_jellyfish_fson_value_t* native() { return &v_; }

            /**
             * @brief Access native pointer (const).
             */
            const fossil_ai_jellyfish_fson_value_t* native() const { return &v_; }
        private:
            fossil_ai_jellyfish_fson_value_t v_;
        };

        // ---- Block FSON attachments ----

        /**
         * @brief Insert semantic key/value into block classification meta.
         */
        static int block_set_semantic_kv(fossil_ai_jellyfish_block_t* block,
                                         const char* key,
                                         fossil_ai_jellyfish_fson_value_t* value) {
            return ::fossil_ai_jellyfish_block_set_semantic_kv(block, key, value);
        }

        /**
         * @brief Attach arbitrary FSON node to block attachments list.
         */
        static int block_add_attachment(fossil_ai_jellyfish_block_t* block,
                                        fossil_ai_jellyfish_fson_value_t* attachment) {
            return ::fossil_ai_jellyfish_block_add_attachment(block, attachment);
        }

        /**
         * @brief Set audit metadata object for block.
         */
        static int block_set_audit_meta(fossil_ai_jellyfish_block_t* block,
                                        fossil_ai_jellyfish_fson_value_t* meta) {
            return ::fossil_ai_jellyfish_block_set_audit_meta(block, meta);
        }

        // ---- Repo meta ----

        /**
         * @brief Insert repository-level metadata key/value.
         */
        int repo_meta_put(const char* key, fossil_ai_jellyfish_fson_value_t* value) {
            return ::fossil_ai_jellyfish_repo_meta_put(&chain_, key, value);
        }

        // ---- Crypto ----

        /**
         * @brief Sign block (delegates to C cryptographic implementation).
         */
        static int block_sign(fossil_ai_jellyfish_block_t* block, const uint8_t* priv_key) {
            return ::fossil_ai_jellyfish_block_sign(block, priv_key);
        }

        /**
         * @brief Verify block signature.
         */
        static bool block_verify_signature(const fossil_ai_jellyfish_block_t* block,
                                           const uint8_t* pub_key) {
            return ::fossil_ai_jellyfish_block_verify_signature(block, pub_key);
        }

        // ---- Tokenization ----

        /**
         * @brief Tokenize input (lowercase alphanumeric).
         */
        size_t tokenize(const char* input,
                        char tokens[][FOSSIL_JELLYFISH_TOKEN_SIZE],
                        size_t max_tokens) const {
            return ::fossil_ai_jellyfish_tokenize(input, tokens, max_tokens);
        }

        // ---- Utility ----

        /**
         * @brief Compute age for a block relative to supplied now.
         */
        static uint64_t block_age(const fossil_ai_jellyfish_block_t* block, uint64_t now) {
            return ::fossil_ai_jellyfish_block_age(block, now);
        }

        /**
         * @brief Produce concise diagnostic description for block.
         */
        static void block_explain(const fossil_ai_jellyfish_block_t* block, char* out, size_t size) {
            ::fossil_ai_jellyfish_block_explain(block, out, size);
        }

        /**
         * @brief Deep clone into destination Jellyfish.
         */
        int clone_chain(Jellyfish& dst) const {
            return ::fossil_ai_jellyfish_clone_chain(&chain_, &dst.chain_);
        }

        /**
         * @brief Mutable native chain pointer.
         */
        fossil_ai_jellyfish_chain_t* native_chain() { return &chain_; }

        /**
         * @brief Const native chain pointer.
         */
        const fossil_ai_jellyfish_chain_t* native_chain() const { return &chain_; }

    private:
        fossil_ai_jellyfish_chain_t chain_; /**< Underlying chain storage */
    };

} // namespace ai

} // namespace fossil

#endif

#endif /* fossil_fish_FRAMEWORK_H */
