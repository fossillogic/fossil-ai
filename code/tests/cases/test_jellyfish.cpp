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
#include <fossil/pizza/framework.h>
#include "fossil/ai/framework.h"


// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Utilities
// * * * * * * * * * * * * * * * * * * * * * * * *
// Setup steps for things like test fixtures and
// mock objects are set here.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_SUITE(cpp_jellyfish_fixture);

FOSSIL_SETUP(cpp_jellyfish_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_jellyfish_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

using fossil::ai::Jellyfish;

FOSSIL_TEST_CASE(cpp_test_jellyfish_hash_basic) {
    const char *input = "hello";
    const char *output = "world";
    uint8_t hash[32] = {0};

    Jellyfish::hash(input, output, hash);

    int nonzero = 0;
    for (size_t i = 0; i < sizeof(hash); ++i) {
        if (hash[i] != 0) { nonzero = 1; break; }
    }
    ASSUME_ITS_TRUE(nonzero);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_hash_consistency) {
    const char *input = "repeat";
    const char *output = "test";
    uint8_t hash1[32] = {0};
    uint8_t hash2[32] = {0};

    Jellyfish::hash(input, output, hash1);
    Jellyfish::hash(input, output, hash2);

    ASSUME_ITS_TRUE(memcmp(hash1, hash2, sizeof(hash1)) == 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_hash_difference) {
    const char *input1 = "foo";
    const char *output1 = "bar";
    const char *input2 = "baz";
    const char *output2 = "qux";
    uint8_t hash1[32] = {0};
    uint8_t hash2[32] = {0};

    Jellyfish::hash(input1, output1, hash1);
    Jellyfish::hash(input2, output2, hash2);

    int different = 0;
    for (size_t i = 0; i < sizeof(hash1); ++i) {
        if (hash1[i] != hash2[i]) { different = 1; break; }
    }
    ASSUME_ITS_TRUE(different);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_init_zeroes_chain) {
    Jellyfish jf;
    jf.init();
    ASSUME_ITS_EQUAL_I32((int)jf.native_chain()->count, 0);
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i) {
        int all_zero = 1;
        const uint8_t *mem = (const uint8_t *)&jf.native_chain()->commits[i];
        for (size_t j = 0; j < sizeof(jf.native_chain()->commits[i]); ++j) {
            if (mem[j] != 0) { all_zero = 0; break; }
        }
        ASSUME_ITS_TRUE(all_zero);
    }
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_learn_and_find) {
    Jellyfish jf;

    const char *input = "cat";
    const char *output = "meow";
    uint8_t hash[FOSSIL_JELLYFISH_HASH_SIZE] = {0};

    jf.learn(input, output);
    Jellyfish::hash(input, output, hash);

    fossil_ai_jellyfish_block_t *found = jf.find(hash);
    ASSUME_ITS_TRUE(found != NULL);
    ASSUME_ITS_EQUAL_CSTR(found->io.input, input);
    ASSUME_ITS_EQUAL_CSTR(found->io.output, output);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_update_block) {
    Jellyfish jf;

    jf.learn("dog", "bark");
    size_t idx = 0;
    for (; idx < FOSSIL_JELLYFISH_MAX_MEM; ++idx) {
        if (jf.native_chain()->commits[idx].attributes.valid) break;
    }
    ASSUME_ITS_TRUE(idx < FOSSIL_JELLYFISH_MAX_MEM);

    jf.update(idx, "dog", "woof");
    ASSUME_ITS_EQUAL_CSTR(jf.native_chain()->commits[idx].io.input, "dog");
    ASSUME_ITS_EQUAL_CSTR(jf.native_chain()->commits[idx].io.output, "woof");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_remove_block) {
    Jellyfish jf;

    jf.learn("bird", "tweet");
    size_t idx = 0;
    for (; idx < FOSSIL_JELLYFISH_MAX_MEM; ++idx) {
        if (jf.native_chain()->commits[idx].attributes.valid) break;
    }
    ASSUME_ITS_TRUE(idx < FOSSIL_JELLYFISH_MAX_MEM);

    jf.remove(idx);
    ASSUME_ITS_FALSE(jf.native_chain()->commits[idx].attributes.valid);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_save_and_load) {
    Jellyfish jf;
    Jellyfish loaded;

    jf.learn("sun", "shine");
    jf.learn("moon", "glow");

    const char *filepath = "test_jellyfish_save.bin";
    int save_result = jf.save(filepath);
    ASSUME_ITS_EQUAL_I32(save_result, 0);

    int load_result = loaded.load(filepath);
    ASSUME_ITS_EQUAL_I32(load_result, 0);

    ASSUME_ITS_EQUAL_I32((int)jf.native_chain()->count, (int)loaded.native_chain()->count);
    for (size_t i = 0; i < jf.native_chain()->count; ++i) {
        ASSUME_ITS_EQUAL_CSTR(jf.native_chain()->commits[i].io.input,
                              loaded.native_chain()->commits[i].io.input);
        ASSUME_ITS_EQUAL_CSTR(jf.native_chain()->commits[i].io.output,
                              loaded.native_chain()->commits[i].io.output);
    }
    remove(filepath);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_load_invalid_file) {
    Jellyfish jf;
    int result = jf.load("nonexistent_file.bin");
    ASSUME_ITS_TRUE(result < 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_cleanup_removes_invalid_blocks) {
    Jellyfish jf;

    jf.learn("a", "1");
    jf.learn("b", "2");
    jf.native_chain()->commits[0].attributes.valid = 0;

    jf.cleanup();

    size_t valid_count = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_MAX_MEM; ++i)
        if (jf.native_chain()->commits[i].attributes.valid) valid_count++;
    ASSUME_ITS_EQUAL_I32((int)valid_count, 1);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_audit_detects_duplicate_hash) {
    Jellyfish jf;

    jf.learn("dup", "val");
    jf.learn("dup", "val");

    int issues = jf.audit();
    ASSUME_ITS_TRUE(issues > 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_prune_low_confidence) {
    Jellyfish jf;

    jf.learn("x", "y");
    jf.native_chain()->commits[0].attributes.confidence = 0.01f;

    int pruned = jf.prune(0.5f);
    ASSUME_ITS_EQUAL_I32(pruned, 1);
    ASSUME_ITS_FALSE(jf.native_chain()->commits[0].attributes.valid);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_reason_returns_output) {
    Jellyfish jf;

    jf.learn("input", "output");
    const char *result = jf.reason("input");
    ASSUME_ITS_EQUAL_CSTR(result, "output");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_reason_returns_unknown) {
    Jellyfish jf;

    const char *result = jf.reason("notfound");
    ASSUME_ITS_EQUAL_CSTR(result, "Unknown");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_decay_confidence) {
    Jellyfish jf;

    jf.learn("decay", "test");
    jf.native_chain()->commits[0].attributes.confidence = 1.0f;

    jf.decay_confidence(0.5f);

    ASSUME_ITS_TRUE(jf.native_chain()->commits[0].attributes.confidence < 1.0f);
    ASSUME_ITS_TRUE(jf.native_chain()->commits[0].attributes.confidence > 0.0f);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_tokenize_basic) {
    Jellyfish jf;
    char tokens[8][16];
    size_t n = jf.tokenize("Hello, world! This is a test.", tokens, 8);

    ASSUME_ITS_TRUE(n > 0);
    ASSUME_ITS_EQUAL_CSTR(tokens[0], "hello");
    ASSUME_ITS_EQUAL_CSTR(tokens[1], "world");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_best_memory_returns_highest_confidence) {
    Jellyfish jf;

    jf.learn("a", "1");
    jf.learn("b", "2");
    jf.native_chain()->commits[0].attributes.confidence = 0.1f;
    jf.native_chain()->commits[1].attributes.confidence = 0.9f;

    const fossil_ai_jellyfish_block_t *best = jf.best_memory();
    ASSUME_ITS_TRUE(best != NULL);
    ASSUME_ITS_TRUE(fabsf(best->attributes.confidence - 0.9f) < 0.0001f);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_knowledge_coverage_basic) {
    Jellyfish jf;

    float coverage_empty = jf.knowledge_coverage();
    ASSUME_ITS_TRUE(fabsf(coverage_empty - 0.0f) < 0.00001f);

    jf.learn("foo", "bar");
    float coverage_nonempty = jf.knowledge_coverage();
    ASSUME_ITS_TRUE(coverage_nonempty > 0.0f && coverage_nonempty <= 1.0f);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_detect_conflict) {
    Jellyfish jf;

    jf.learn("input", "output1");
    int conflict = jf.detect_conflict("input", "output2");
    ASSUME_ITS_TRUE(conflict != 0);

    int no_conflict = jf.detect_conflict("input", "output1");
    ASSUME_ITS_EQUAL_I32(no_conflict, 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_verify_block_valid_and_invalid) {
    fossil_ai_jellyfish_block_t block;
    memset(&block, 0, sizeof(block));
    strcpy(block.io.input, "abc");
    strcpy(block.io.output, "def");
    for (size_t i = 0; i < FOSSIL_JELLYFISH_HASH_SIZE; ++i)
        block.identity.commit_hash[i] = (uint8_t)(i + 1);

    bool valid = Jellyfish::verify_block(&block);
    ASSUME_ITS_TRUE(valid);

    block.io.input[0] = '\0';
    ASSUME_ITS_FALSE(Jellyfish::verify_block(&block));
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_verify_chain_all_valid) {
    Jellyfish jf;
    jf.learn("alpha", "beta");
    jf.learn("gamma", "delta");

    bool ok = jf.verify_chain();
    ASSUME_ITS_TRUE(ok);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_verify_chain_with_invalid_block) {
    Jellyfish jf;
    jf.learn("one", "two");
    jf.native_chain()->commits[0].io.input[0] = '\0';

    bool ok = jf.verify_chain();
    ASSUME_ITS_FALSE(ok);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_trust_score_empty) {
    Jellyfish jf;

    float score = jf.chain_trust_score();
    ASSUME_ITS_TRUE(fabsf(score - 0.0f) < 0.00001f);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_trust_score_immutable_blocks) {
    Jellyfish jf;

    jf.learn("core", "logic");
    jf.learn("aux", "data");
    Jellyfish::mark_immutable(&jf.native_chain()->commits[0]);
    jf.native_chain()->commits[0].attributes.confidence = 1.0f;
    jf.native_chain()->commits[1].attributes.confidence = 0.5f;

    float score = jf.chain_trust_score();
    ASSUME_ITS_TRUE(score > 0.0f && score <= 1.0f);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_mark_immutable_sets_flag) {
    Jellyfish jf;

    jf.learn("persist", "forever");
    Jellyfish::mark_immutable(&jf.native_chain()->commits[0]);
    ASSUME_ITS_TRUE(jf.native_chain()->commits[0].attributes.immutable);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_deduplicate_chain_removes_duplicates) {
    Jellyfish jf;

    jf.learn("dup", "val");
    jf.learn("dup", "val");
    size_t before = jf.native_chain()->count;

    int removed = jf.deduplicate_chain();
    ASSUME_ITS_TRUE(removed > 0);
    ASSUME_ITS_TRUE(jf.native_chain()->count < before);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_compress_chain_trims_whitespace) {
    Jellyfish jf;

    jf.learn("  spaced  ", "  out  ");
    int modified = jf.compress_chain();
    ASSUME_ITS_TRUE(modified > 0);
    ASSUME_ITS_EQUAL_CSTR(jf.native_chain()->commits[0].io.input, "spaced");
    ASSUME_ITS_EQUAL_CSTR(jf.native_chain()->commits[0].io.output, "out");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_best_match_returns_most_confident) {
    Jellyfish jf;

    jf.learn("input", "first");
    jf.learn("input", "second");
    jf.native_chain()->commits[0].attributes.confidence = 0.2f;
    jf.native_chain()->commits[1].attributes.confidence = 0.9f;

    const fossil_ai_jellyfish_block_t *best = jf.best_match("input");
    ASSUME_ITS_TRUE(best != NULL);
    ASSUME_ITS_EQUAL_CSTR(best->io.output, "second");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_redact_block_redacts_fields) {
    fossil_ai_jellyfish_block_t block;
    memset(&block, 0, sizeof(block));
    strcpy(block.io.input, "secret_input");
    strcpy(block.io.output, "secret_output");
    for (size_t i = 0; i < FOSSIL_JELLYFISH_HASH_SIZE; ++i)
        block.identity.commit_hash[i] = (uint8_t)(i + 1);

    int result = Jellyfish::redact_block(&block);
    ASSUME_ITS_EQUAL_I32(result, 0);
    ASSUME_ITS_TRUE(strstr(block.io.input, "REDACTED") != NULL);
    ASSUME_ITS_TRUE(strstr(block.io.output, "REDACTED") != NULL);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_stats_basic) {
    Jellyfish jf;
    jf.learn("a", "1");
    jf.learn("b", "2");
    jf.native_chain()->commits[0].attributes.immutable = 1;

    size_t valid_count[5] = {0};
    float avg_conf[5] = {0};
    float immut_ratio[5] = {0};

    jf.chain_stats(valid_count, avg_conf, immut_ratio);

    size_t total_valid = 0;
    for (int i = 0; i < 5; ++i) total_valid += valid_count[i];
    ASSUME_ITS_TRUE(total_valid > 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_compare_chains_detects_difference) {
    Jellyfish a;
    Jellyfish b;

    a.learn("x", "y");
    b.learn("x", "z");

    int diff = a.compare_chains(b);
    ASSUME_ITS_TRUE(diff > 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_fingerprint_changes_on_update) {
    Jellyfish jf;

    uint8_t hash1[FOSSIL_JELLYFISH_HASH_SIZE] = {0};
    uint8_t hash2[FOSSIL_JELLYFISH_HASH_SIZE] = {0};

    jf.learn("foo", "bar");
    jf.chain_fingerprint(hash1);

    jf.learn("baz", "qux");
    jf.chain_fingerprint(hash2);

    int different = 0;
    for (size_t i = 0; i < FOSSIL_JELLYFISH_HASH_SIZE; ++i) {
        if (hash1[i] != hash2[i]) { different = 1; break; }
    }
    ASSUME_ITS_TRUE(different);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_trim_reduces_block_count) {
    Jellyfish jf;

    for (int i = 0; i < 5; ++i) {
        char in[8], out[8];
        snprintf(in, sizeof(in), "in%d", i);
        snprintf(out, sizeof(out), "out%d", i);
        jf.learn(in, out);
    }
    size_t before = jf.native_chain()->count;
    int removed = jf.trim(2);
    ASSUME_ITS_TRUE(removed > 0);
    ASSUME_ITS_TRUE(jf.native_chain()->count <= 2);
    ASSUME_ITS_TRUE(before > jf.native_chain()->count);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_compact_moves_blocks) {
    Jellyfish jf;

    jf.learn("a", "1");
    jf.learn("b", "2");
    jf.native_chain()->commits[0].attributes.valid = 0;

    int moved = jf.chain_compact();
    ASSUME_ITS_TRUE(moved > 0);
    ASSUME_ITS_TRUE(jf.native_chain()->commits[0].attributes.valid);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_block_age_basic) {
    fossil_ai_jellyfish_block_t block;
    memset(&block, 0, sizeof(block));
    block.time.timestamp = 1000000;
    uint64_t now = 1005000;
    uint64_t age = Jellyfish::block_age(&block, now);
    ASSUME_ITS_EQUAL_I32((int)age, 5000);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_block_explain_outputs_string) {
    fossil_ai_jellyfish_block_t block;
    memset(&block, 0, sizeof(block));
    strcpy(block.io.input, "explain_in");
    strcpy(block.io.output, "explain_out");
    block.attributes.confidence = 0.75f;
    block.attributes.valid = 1;
    char buf[256] = {0};
    Jellyfish::block_explain(&block, buf, sizeof(buf));
    ASSUME_ITS_TRUE(strstr(buf, "explain_in") != NULL);
    ASSUME_ITS_TRUE(strstr(buf, "explain_out") != NULL);
    ASSUME_ITS_TRUE(strstr(buf, "0.75") != NULL);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_find_by_hash_finds_block) {
    Jellyfish jf;
    jf.learn("findme", "found");
    uint8_t hash[FOSSIL_JELLYFISH_HASH_SIZE] = {0};
    Jellyfish::hash("findme", "found", hash);
    const fossil_ai_jellyfish_block_t *found = jf.find_by_hash(hash);
    ASSUME_ITS_TRUE(found != NULL);
    ASSUME_ITS_EQUAL_CSTR(found->io.input, "findme");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_find_by_hash_returns_null_for_missing) {
    Jellyfish jf;
    uint8_t hash[FOSSIL_JELLYFISH_HASH_SIZE] = {0};
    memset(hash, 0xAA, sizeof(hash));
    const fossil_ai_jellyfish_block_t *found = jf.find_by_hash(hash);
    ASSUME_ITS_TRUE(found == NULL);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_clone_chain_copies_all_blocks) {
    Jellyfish src;
    Jellyfish dst;
    src.learn("clone", "me");
    int result = src.clone_chain(dst);
    ASSUME_ITS_EQUAL_I32(result, 0);
    ASSUME_ITS_EQUAL_I32((int)src.native_chain()->count, (int)dst.native_chain()->count);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_reason_verbose_returns_match) {
    Jellyfish jf;
    jf.learn("input", "output");
    char out[64] = {0};
    float conf = 0.0f;
    const fossil_ai_jellyfish_block_t *block = NULL;
    bool found = jf.reason_verbose("input", out, &conf, &block);
    ASSUME_ITS_TRUE(found);
    ASSUME_ITS_EQUAL_CSTR(out, "output");
    ASSUME_ITS_TRUE(conf > 0.0f);
    ASSUME_ITS_TRUE(block != NULL);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_reason_verbose_returns_false_for_no_match) {
    Jellyfish jf;
    char out[64] = {0};
    float conf = 0.0f;
    const fossil_ai_jellyfish_block_t *block = NULL;
    bool found = jf.reason_verbose("nope", out, &conf, &block);
    ASSUME_ITS_FALSE(found);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_jellyfish_tests) {    
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_hash_basic);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_hash_consistency);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_hash_difference);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_init_zeroes_chain);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_learn_and_find);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_update_block);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_remove_block);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_save_and_load);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_load_invalid_file);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_cleanup_removes_invalid_blocks);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_audit_detects_duplicate_hash);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_prune_low_confidence);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_reason_returns_output);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_reason_returns_unknown);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_decay_confidence);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_tokenize_basic);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_best_memory_returns_highest_confidence);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_knowledge_coverage_basic);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_detect_conflict);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_verify_block_valid_and_invalid);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_verify_chain_all_valid);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_verify_chain_with_invalid_block);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_chain_trust_score_empty);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_chain_trust_score_immutable_blocks);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_mark_immutable_sets_flag);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_deduplicate_chain_removes_duplicates);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_compress_chain_trims_whitespace);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_best_match_returns_most_confident);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_redact_block_redacts_fields);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_chain_stats_basic);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_compare_chains_detects_difference);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_chain_fingerprint_changes_on_update);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_trim_reduces_block_count);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_chain_compact_moves_blocks);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_block_age_basic);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_block_explain_outputs_string);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_find_by_hash_finds_block);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_find_by_hash_returns_null_for_missing);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_clone_chain_copies_all_blocks);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_reason_verbose_returns_match);
    FOSSIL_TEST_ADD(cpp_jellyfish_fixture, cpp_test_jellyfish_reason_verbose_returns_false_for_no_match);

    FOSSIL_TEST_REGISTER(cpp_jellyfish_fixture);
} // end of tests
