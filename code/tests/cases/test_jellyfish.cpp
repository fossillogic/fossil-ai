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

// C++ wrapper based tests
FOSSIL_TEST_CASE(cpp_test_jellyfish_hash_basic) {
    uint8_t hash[32] = {0};
    fossil::ai::Jellyfish::hash("hello", "world", hash);
    int nonzero = 0;
    for (size_t i = 0; i < sizeof(hash); ++i) if (hash[i]) { nonzero = 1; break; }
    ASSUME_ITS_TRUE(nonzero);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_hash_consistency) {
    uint8_t h1[32] = {0}, h2[32] = {0};
    fossil::ai::Jellyfish::hash("repeat", "test", h1);
    fossil::ai::Jellyfish::hash("repeat", "test", h2);
    ASSUME_ITS_TRUE(memcmp(h1, h2, sizeof(h1)) == 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_hash_difference) {
    uint8_t h1[32] = {0}, h2[32] = {0};
    fossil::ai::Jellyfish::hash("foo", "bar", h1);
    fossil::ai::Jellyfish::hash("baz", "qux", h2);
    ASSUME_ITS_TRUE(memcmp(h1, h2, sizeof(h1)) != 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_init_zeroes_chain) {
    fossil::ai::Jellyfish j;
    j.init(); // explicit re-init
    auto *chain = j.native_chain();
    ASSUME_ITS_EQUAL_I32((int)chain->count, 0);
    ASSUME_ITS_EQUAL_I32((int)chain->branch_count, 1);
    ASSUME_ITS_EQUAL_CSTR(chain->default_branch, "main");
    ASSUME_ITS_TRUE(chain->created_at != 0);
    ASSUME_ITS_TRUE(chain->updated_at != 0);
    int rid_nonzero = 0;
    for (size_t i = 0; i < FOSSIL_DEVICE_ID_SIZE; ++i) if (chain->repo_id[i]) { rid_nonzero = 1; break; }
    ASSUME_ITS_TRUE(rid_nonzero);
    for (size_t i = 0; i < 8; ++i) {
        ASSUME_ITS_EQUAL_I32((int)chain->commits[i].identity.commit_index, (int)i);
        ASSUME_ITS_FALSE(chain->commits[i].attributes.valid);
        ASSUME_ITS_TRUE(fabsf(chain->commits[i].attributes.confidence - 0.0f) < 0.00001f);
    }
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_learn_and_find) {
    fossil::ai::Jellyfish j;
    j.learn("cat", "meow");
    uint8_t h[FOSSIL_JELLYFISH_HASH_SIZE] = {0};
    fossil::ai::Jellyfish::hash("cat", "meow", h);
    auto *blk = j.find(h);
    ASSUME_ITS_TRUE(blk != NULL);
    ASSUME_ITS_EQUAL_CSTR(blk->io.input, "cat");
    ASSUME_ITS_EQUAL_CSTR(blk->io.output, "meow");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_update_block) {
    fossil::ai::Jellyfish j;
    j.learn("dog", "bark");
    auto *chain = j.native_chain();
    size_t idx = 0;
    while (idx < FOSSIL_JELLYFISH_MAX_MEM && !chain->commits[idx].attributes.valid) ++idx;
    ASSUME_ITS_TRUE(idx < FOSSIL_JELLYFISH_MAX_MEM);
    j.update(idx, "dog", "woof");
    ASSUME_ITS_EQUAL_CSTR(chain->commits[idx].io.output, "woof");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_remove_block) {
    fossil::ai::Jellyfish j;
    j.learn("bird", "tweet");
    auto *chain = j.native_chain();
    size_t idx = 0;
    while (idx < FOSSIL_JELLYFISH_MAX_MEM && !chain->commits[idx].attributes.valid) ++idx;
    ASSUME_ITS_TRUE(idx < FOSSIL_JELLYFISH_MAX_MEM);
    j.remove(idx);
    ASSUME_ITS_FALSE(chain->commits[idx].attributes.valid);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_save_and_load) {
    fossil::ai::Jellyfish a, b;
    a.learn("sun", "shine");
    a.learn("moon", "glow");
    const char *file = "test_jellyfish_save.bin";
    ASSUME_ITS_EQUAL_I32(a.save(file), 0);
    ASSUME_ITS_EQUAL_I32(b.load(file), 0);
    ASSUME_ITS_EQUAL_I32((int)a.native_chain()->count, (int)b.native_chain()->count);
    remove(file);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_load_invalid_file) {
    fossil::ai::Jellyfish j;
    ASSUME_ITS_TRUE(j.load("no_file.bin") < 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_cleanup_removes_invalid_blocks) {
    fossil::ai::Jellyfish j;
    j.learn("a","1"); j.learn("b","2");
    auto *c = j.native_chain();
    c->commits[0].attributes.valid = 0;
    j.cleanup();
    size_t vc = 0;
    for (size_t i=0;i<FOSSIL_JELLYFISH_MAX_MEM;++i) if (c->commits[i].attributes.valid) ++vc;
    ASSUME_ITS_EQUAL_I32((int)vc,1);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_audit_detects_duplicate_hash) {
    fossil::ai::Jellyfish j;
    j.learn("dup","val");
    j.learn("dup","val");
    ASSUME_ITS_TRUE(j.audit() > 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_prune_low_confidence) {
    fossil::ai::Jellyfish j;
    j.learn("x","y");
    j.native_chain()->commits[0].attributes.confidence = 0.01f;
    int pruned = j.prune(0.5f);
    ASSUME_ITS_EQUAL_I32(pruned,1);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_reason_returns_output) {
    fossil::ai::Jellyfish j;
    j.learn("input","output");
    ASSUME_ITS_EQUAL_CSTR(j.reason("input"), "output");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_reason_returns_unknown) {
    fossil::ai::Jellyfish j;
    ASSUME_ITS_EQUAL_CSTR(j.reason("none"), "Unknown");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_decay_confidence) {
    fossil::ai::Jellyfish j;
    j.learn("decay","test");
    j.native_chain()->commits[0].attributes.confidence = 1.0f;
    j.decay_confidence(0.5f);
    ASSUME_ITS_TRUE(j.native_chain()->commits[0].attributes.confidence < 1.0f);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_tokenize_basic) {
    fossil::ai::Jellyfish j;
    char toks[8][16];
    size_t n = j.tokenize("Hello, world! This is a test.", toks, 8);
    ASSUME_ITS_TRUE(n > 0);
    ASSUME_ITS_EQUAL_CSTR(toks[0], "hello");
    ASSUME_ITS_EQUAL_CSTR(toks[1], "world");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_best_memory_returns_highest_confidence) {
    fossil::ai::Jellyfish j;
    j.learn("a","1");
    j.learn("b","2");
    auto *c = j.native_chain();
    c->commits[0].attributes.confidence = 0.1f;
    c->commits[1].attributes.confidence = 0.9f;
    auto *best = j.best_memory();
    ASSUME_ITS_TRUE(best && fabsf(best->attributes.confidence - 0.9f) < 0.0001f);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_knowledge_coverage_basic) {
    fossil::ai::Jellyfish j;
    float c0 = j.knowledge_coverage();
    ASSUME_ITS_TRUE(fabsf(c0 - 0.0f) < 0.00001f);
    j.learn("foo","bar");
    float c1 = j.knowledge_coverage();
    ASSUME_ITS_TRUE(c1 > 0.0f && c1 <= 1.0f);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_detect_conflict) {
    fossil::ai::Jellyfish j;
    j.learn("input","output1");
    ASSUME_ITS_TRUE(j.detect_conflict("input","output2") != 0);
    ASSUME_ITS_EQUAL_I32(j.detect_conflict("input","output1"), 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_verify_block_valid_and_invalid) {
    fossil_ai_jellyfish_block_t b;
    memset(&b,0,sizeof(b));
    strcpy(b.io.input,"abc");
    strcpy(b.io.output,"def");
    b.io.input_len = (uint32_t)strlen(b.io.input);
    b.io.output_len = (uint32_t)strlen(b.io.output);
    b.block_type = JELLY_COMMIT_INFER;
    fossil::ai::Jellyfish::hash(b.io.input, b.io.output, b.identity.commit_hash);
    bool ok = fossil::ai::Jellyfish::verify_block(&b);
    ASSUME_ITS_TRUE(ok);
    b.io.input[0] = 0;
    ASSUME_ITS_FALSE(fossil::ai::Jellyfish::verify_block(&b));
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_verify_chain_all_valid) {
    fossil::ai::Jellyfish j;
    j.learn("alpha","beta");
    j.learn("gamma","delta");
    ASSUME_ITS_TRUE(j.verify_chain());
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_verify_chain_with_invalid_block) {
    fossil::ai::Jellyfish j;
    j.learn("one","two");
    j.native_chain()->commits[0].io.input[0] = 0;
    ASSUME_ITS_FALSE(j.verify_chain());
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_trust_score_empty) {
    fossil::ai::Jellyfish j;
    ASSUME_ITS_TRUE(fabsf(j.chain_trust_score() - 0.0f) < 0.00001f);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_trust_score_immutable_blocks) {
    fossil::ai::Jellyfish j;
    j.learn("core","logic");
    j.learn("aux","data");
    fossil::ai::Jellyfish::mark_immutable(&j.native_chain()->commits[0]);
    j.native_chain()->commits[0].attributes.confidence = 1.0f;
    j.native_chain()->commits[1].attributes.confidence = 0.5f;
    float s = j.chain_trust_score();
    ASSUME_ITS_TRUE(s > 0.0f && s <= 1.0f);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_mark_immutable_sets_flag) {
    fossil::ai::Jellyfish j;
    j.learn("persist","forever");
    fossil::ai::Jellyfish::mark_immutable(&j.native_chain()->commits[0]);
    ASSUME_ITS_TRUE(j.native_chain()->commits[0].attributes.immutable);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_deduplicate_chain_removes_duplicates) {
    fossil::ai::Jellyfish j;
    j.learn("dup","val");
    j.learn("dup","val");
    size_t before = j.native_chain()->count;
    int removed = j.deduplicate_chain();
    ASSUME_ITS_TRUE(removed >= 0);
    ASSUME_ITS_TRUE(j.native_chain()->count <= before);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_compress_chain_trims_whitespace) {
    fossil::ai::Jellyfish j;
    j.learn("  spaced  ","  out  ");
    int mod = j.compress_chain();
    ASSUME_ITS_TRUE(mod > 0);
    ASSUME_ITS_EQUAL_CSTR(j.native_chain()->commits[0].io.input,"spaced");
    ASSUME_ITS_EQUAL_CSTR(j.native_chain()->commits[0].io.output,"out");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_best_match_returns_most_confident) {
    fossil::ai::Jellyfish j;
    j.learn("input","first");
    j.learn("input","second");
    j.native_chain()->commits[0].attributes.confidence = 0.2f;
    j.native_chain()->commits[1].attributes.confidence = 0.9f;
    auto *best = j.best_match("input");
    ASSUME_ITS_TRUE(best);
    ASSUME_ITS_EQUAL_CSTR(best->io.output,"second");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_redact_block_redacts_fields) {
    fossil_ai_jellyfish_block_t b;
    memset(&b,0,sizeof(b));
    strcpy(b.io.input,"contact me at user@example.com");
    strcpy(b.io.output,"uuid 550e8400-e29b-41d4-a716-446655440000");
    b.io.input_len = (uint32_t)strlen(b.io.input);
    b.io.output_len = (uint32_t)strlen(b.io.output);
    b.block_type = JELLY_COMMIT_INFER;
    b.attributes.confidence = 0.8f;
    b.attributes.valid = 1;
    fossil::ai::Jellyfish::hash(b.io.input,b.io.output,b.identity.commit_hash);
    char in_orig[128]; char out_orig[128];
    strcpy(in_orig,b.io.input); strcpy(out_orig,b.io.output);
    int r = fossil::ai::Jellyfish::redact_block(&b);
    ASSUME_ITS_TRUE(r > 0);
    ASSUME_ITS_FALSE(strcmp(in_orig,b.io.input)==0);
    ASSUME_ITS_FALSE(strcmp(out_orig,b.io.output)==0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_stats_basic) {
    fossil::ai::Jellyfish j;
    j.learn("a","1");
    j.learn("b","2");
    j.native_chain()->commits[0].attributes.immutable = 1;
    size_t vc[5]={0}; float ac[5]={0}; float ir[5]={0};
    j.chain_stats(vc,ac,ir);
    size_t total=0; for(int i=0;i<5;++i) total+=vc[i];
    ASSUME_ITS_TRUE(total>0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_compare_chains_detects_difference) {
    fossil::ai::Jellyfish a,b;
    a.learn("x","y");
    b.learn("x","z");
    ASSUME_ITS_TRUE(a.compare_chains(b) > 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_fingerprint_changes_on_update) {
    fossil::ai::Jellyfish j;
    uint8_t h1[FOSSIL_JELLYFISH_HASH_SIZE]={0}, h2[FOSSIL_JELLYFISH_HASH_SIZE]={0};
    j.learn("foo","bar");
    j.chain_fingerprint(h1);
    j.learn("baz","qux");
    j.chain_fingerprint(h2);
    ASSUME_ITS_TRUE(memcmp(h1,h2,sizeof(h1)) != 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_trim_reduces_block_count) {
    fossil::ai::Jellyfish j;
    for (int i=0;i<5;++i) {
        char in[8], out[8];
        snprintf(in,sizeof(in),"in%d",i);
        snprintf(out,sizeof(out),"out%d",i);
        j.learn(in,out);
    }
    size_t before = j.native_chain()->count;
    j.trim(2);
    ASSUME_ITS_TRUE(j.native_chain()->count <= 2);
    ASSUME_ITS_TRUE(before >= j.native_chain()->count);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_compact_moves_blocks) {
    fossil::ai::Jellyfish j;
    j.learn("a","1");
    j.learn("b","2");
    j.native_chain()->commits[0].attributes.valid = 0;
    j.chain_compact();
    ASSUME_ITS_TRUE(j.native_chain()->commits[0].attributes.valid);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_block_age_basic) {
    fossil_ai_jellyfish_block_t b;
    memset(&b,0,sizeof(b));
    b.time.timestamp = 1000000;
    uint64_t age = fossil::ai::Jellyfish::block_age(&b, 1005000);
    ASSUME_ITS_EQUAL_I32((int)age,5000);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_block_explain_outputs_string) {
    fossil_ai_jellyfish_block_t b;
    memset(&b,0,sizeof(b));
    strcpy(b.io.input,"explain_in");
    strcpy(b.io.output,"explain_out");
    b.io.input_len = (uint32_t)strlen(b.io.input);
    b.io.output_len = (uint32_t)strlen(b.io.output);
    b.attributes.confidence = 0.75f;
    b.attributes.valid = 1;
    b.block_type = JELLY_COMMIT_INFER;
    char buf[256]={0};
    fossil::ai::Jellyfish::block_explain(&b, buf, sizeof(buf));
    ASSUME_ITS_TRUE(strstr(buf,"explain_in")!=NULL);
    ASSUME_ITS_TRUE(strstr(buf,"explain_out")!=NULL);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_find_by_hash_finds_block) {
    fossil::ai::Jellyfish j;
    j.learn("findme","found");
    uint8_t h[FOSSIL_JELLYFISH_HASH_SIZE]={0};
    fossil::ai::Jellyfish::hash("findme","found",h);
    auto *blk = j.find_by_hash(h);
    ASSUME_ITS_TRUE(blk != NULL);
    ASSUME_ITS_EQUAL_CSTR(blk->io.input,"findme");
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_find_by_hash_returns_null_for_missing) {
    fossil::ai::Jellyfish j;
    uint8_t h[FOSSIL_JELLYFISH_HASH_SIZE];
    memset(h,0xAA,sizeof(h));
    ASSUME_ITS_TRUE(j.find_by_hash(h) == NULL);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_clone_chain_copies_all_blocks) {
    fossil::ai::Jellyfish src,dst;
    src.learn("clone","me");
    ASSUME_ITS_TRUE(src.clone_chain(dst) >= 0);
    ASSUME_ITS_EQUAL_I32((int)src.native_chain()->count,(int)dst.native_chain()->count);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_reason_verbose_returns_match) {
    fossil::ai::Jellyfish j;
    j.learn("input","output");
    char out[64]={0}; float conf=0.f; const fossil_ai_jellyfish_block_t *blk=nullptr;
    bool ok = j.reason_verbose("input", out, &conf, &blk);
    ASSUME_ITS_TRUE(ok);
    ASSUME_ITS_EQUAL_CSTR(out,"output");
    ASSUME_ITS_TRUE(conf > 0.0f);
    ASSUME_ITS_TRUE(blk != NULL);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_reason_verbose_returns_false_for_no_match) {
    fossil::ai::Jellyfish j;
    char out[64]={0}; float conf=0.f; const fossil_ai_jellyfish_block_t *blk=nullptr;
    bool ok = j.reason_verbose("nope", out, &conf, &blk);
    ASSUME_ITS_FALSE(ok);
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
