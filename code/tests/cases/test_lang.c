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

FOSSIL_TEST_SUITE(c_lang_fixture);

FOSSIL_SETUP(c_lang_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(c_lang_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

FOSSIL_TEST_CASE(c_test_lang_tokenize_basic) {
    char tokens[8][FOSSIL_JELLYFISH_TOKEN_SIZE] = {0};
    size_t n = fossil_ai_lang_tokenize("Hello, world!  This is a test.", tokens, 8);
    ASSUME_ITS_TRUE(n >= 5 && n <= 7);
    ASSUME_ITS_EQUAL_CSTR(tokens[0], "hello");
    ASSUME_ITS_EQUAL_CSTR(tokens[1], "world");
}

FOSSIL_TEST_CASE(c_test_lang_is_question) {
    ASSUME_ITS_TRUE(fossil_ai_lang_is_question("Is this a question?"));
    ASSUME_ITS_TRUE(fossil_ai_lang_is_question("What time is it"));
    ASSUME_ITS_TRUE(fossil_ai_lang_is_question("Could you help me?"));
    ASSUME_ITS_TRUE(!fossil_ai_lang_is_question("This is not a question."));
}

FOSSIL_TEST_CASE(c_test_lang_detect_emotion) {
    float pos = fossil_ai_lang_detect_emotion("I love this!");
    float neg = fossil_ai_lang_detect_emotion("This is terrible.");
    float neu = fossil_ai_lang_detect_emotion("The sky is blue.");
    ASSUME_ITS_TRUE(pos > neg);
    ASSUME_ITS_TRUE(neg < 0.0f);
    ASSUME_ITS_TRUE(neu > -1.0f && neu < 1.0f);
}

FOSSIL_TEST_CASE(c_test_lang_detect_bias_or_falsehood) {
    int biased_lower = fossil_ai_lang_detect_bias_or_falsehood("everyone knows this is the best!");
    int biased_upper = fossil_ai_lang_detect_bias_or_falsehood("Everyone knows this is the best!");
    int factual = fossil_ai_lang_detect_bias_or_falsehood("The sun rises in the east.");
    ASSUME_ITS_TRUE(biased_lower == 1 || biased_upper == 1);
    ASSUME_ITS_EQUAL_I32(factual, 0);
}

FOSSIL_TEST_CASE(c_test_lang_align_truth) {
    fossil_ai_jellyfish_chain_t chain;
    fossil_ai_jellyfish_init(&chain);
    fossil_ai_iochat_learn_response(&chain, "The sky is blue.", "Yes, it is.");
    int aligned = fossil_ai_lang_align_truth(&chain, "The sky is blue.");
    int unknown = fossil_ai_lang_align_truth(&chain, "Grass is purple.");
    ASSUME_ITS_TRUE(aligned == 1);
    ASSUME_ITS_TRUE(unknown == 0 || unknown == -1);
}

FOSSIL_TEST_CASE(c_test_lang_similarity) {
    float sim1 = fossil_ai_lang_similarity("The quick brown fox", "A quick brown fox");
    float sim2 = fossil_ai_lang_similarity("cat", "dog");
    float sim3 = fossil_ai_lang_similarity("identical", "identical");
    ASSUME_ITS_TRUE(sim1 > sim2);
    ASSUME_ITS_TRUE(sim3 >= 0.95f);
}

FOSSIL_TEST_CASE(c_test_lang_summarize_and_normalize) {
    char summary[64] = {0};
    char normalized[64] = {0};
    fossil_ai_lang_summarize("This is a very long sentence that should be summarized.", summary, sizeof(summary));
    fossil_ai_lang_normalize("I'm gonna win!", normalized, sizeof(normalized));
    ASSUME_ITS_TRUE(summary[0] != '\0');
    ASSUME_ITS_TRUE(strstr(normalized, "going to") != NULL || strstr(normalized, "gonna") != NULL);
}

FOSSIL_TEST_CASE(c_test_lang_extract_focus) {
    char focus[32] = {0};
    fossil_ai_lang_extract_focus("The quick brown fox jumps over the lazy dog.", focus, sizeof(focus));
    ASSUME_ITS_TRUE(focus[0] != '\0');
}

FOSSIL_TEST_CASE(c_test_lang_estimate_trust) {
    fossil_ai_jellyfish_chain_t chain;
    fossil_ai_jellyfish_init(&chain);
    float trust1 = fossil_ai_lang_estimate_trust(&chain, "The sky is blue.");
    float trust2 = fossil_ai_lang_estimate_trust(&chain, "everyone knows this is the best!");
    ASSUME_ITS_TRUE(trust1 >= 0.0f && trust1 <= 1.0f);
    ASSUME_ITS_TRUE(trust2 >= 0.0f && trust2 <= 1.0f);
}

FOSSIL_TEST_CASE(c_test_lang_embedding_similarity) {
    float a[4] = {1.0f, 0.0f, 0.0f, 0.0f};
    float b[4] = {1.0f, 0.0f, 0.0f, 0.0f};
    float c[4] = {0.0f, 1.0f, 0.0f, 0.0f};
    float sim_ab = fossil_ai_lang_embedding_similarity(a, b, 4);
    float sim_ac = fossil_ai_lang_embedding_similarity(a, c, 4);
    ASSUME_ITS_TRUE(sim_ab > sim_ac);
    ASSUME_ITS_TRUE(sim_ab > 0.9f);
}

FOSSIL_TEST_CASE(c_test_lang_generate_variants) {
    char variants[3][256] = {{0}};
    fossil_ai_lang_generate_variants("hello", variants, 3);
    ASSUME_ITS_TRUE(variants[0][0] != '\0');
}

FOSSIL_TEST_CASE(c_test_lang_process_pipeline) {
    fossil_ai_lang_pipeline_t pipe = {
        .normalize = 1,
        .tokenize = 1,
        .detect_emotion = 1,
        .detect_bias = 1,
        .is_question = 1,
        .extract_focus = 1,
        .summarize = 1
    };
    fossil_ai_lang_result_t result = {0};
    const char *input = "Is this gonna win?";
    fossil_ai_lang_process(&pipe, input, &result);
    ASSUME_ITS_TRUE(result.token_count > 0 || result.is_question);
    ASSUME_ITS_TRUE(strstr(result.normalized, "going to") != NULL || strstr(result.normalized, "gonna") != NULL);
    ASSUME_ITS_TRUE(result.focus[0] != '\0');
    ASSUME_ITS_TRUE(result.summary[0] != '\0');
}

FOSSIL_TEST_CASE(c_test_jellyfish_commit_enum_values) {
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_UNKNOWN, 0);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_INIT, 1);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_BRANCH, 10);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_TAG, 20);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_EXPERIMENT, 30);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_SYNC, 40);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_DETACHED, 50);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_FINAL, 54);
}

FOSSIL_TEST_CASE(c_test_jellyfish_block_default_init) {
    fossil_ai_jellyfish_block_t blk = {0};
    ASSUME_ITS_EQUAL_I32(blk.block_type, JELLY_COMMIT_UNKNOWN);
    ASSUME_ITS_EQUAL_I32(blk.identity.parent_count, 0);
    ASSUME_ITS_TRUE(blk.io.input_len == 0 && blk.io.output_len == 0);
}

FOSSIL_TEST_CASE(c_test_jellyfish_chain_basic_init) {
    fossil_ai_jellyfish_chain_t chain = {0};
    ASSUME_ITS_EQUAL_I32(chain.count, 0);
    ASSUME_ITS_TRUE(chain.branch_count == 0);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(c_lang_tests) {
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_tokenize_basic);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_is_question);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_detect_emotion);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_detect_bias_or_falsehood);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_align_truth);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_similarity);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_summarize_and_normalize);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_extract_focus);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_estimate_trust);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_embedding_similarity);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_generate_variants);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_lang_process_pipeline);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_jellyfish_commit_enum_values);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_jellyfish_block_default_init);
    FOSSIL_TEST_ADD(c_lang_fixture, c_test_jellyfish_chain_basic_init);

    FOSSIL_TEST_REGISTER(c_lang_fixture);
} // end of tests
