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

FOSSIL_TEST_SUITE(cpp_lang_fixture);

FOSSIL_SETUP(cpp_lang_fixture) {
    // Setup the test fixture
}

FOSSIL_TEARDOWN(cpp_lang_fixture) {
    // Teardown the test fixture
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Cases
// * * * * * * * * * * * * * * * * * * * * * * * *
// The test cases below are provided as samples, inspired
// by the Meson build system's approach of using test cases
// as samples for library usage.
// * * * * * * * * * * * * * * * * * * * * * * * *

using fossil::ai::Language;

FOSSIL_TEST_CASE(cpp_test_lang_tokenize_basic) {
    // Original C API test
    char tokens[8][FOSSIL_JELLYFISH_TOKEN_SIZE] = {0};
    size_t n = fossil_ai_lang_tokenize("Hello, world!  This is a test.", tokens, 8);
    ASSUME_ITS_EQUAL_I32(n, 6);
    ASSUME_ITS_EQUAL_CSTR(tokens[0], "hello");
    ASSUME_ITS_EQUAL_CSTR(tokens[1], "world");
    ASSUME_ITS_EQUAL_CSTR(tokens[2], "this");
    ASSUME_ITS_EQUAL_CSTR(tokens[3], "is");
    ASSUME_ITS_EQUAL_CSTR(tokens[4], "a");
    ASSUME_ITS_EQUAL_CSTR(tokens[5], "test");

    // C++ wrapper parity
    auto vtoks = Language::tokenize("Hello, world!  This is a test.");
    ASSUME_ITS_EQUAL_I32((int)vtoks.size(), 6);
    ASSUME_ITS_TRUE(vtoks[0] == "hello" && vtoks[5] == "test");
}

FOSSIL_TEST_CASE(cpp_test_lang_is_question) {
    ASSUME_ITS_TRUE(fossil_ai_lang_is_question("Is this a question?"));
    ASSUME_ITS_TRUE(fossil_ai_lang_is_question("What time is it"));
    ASSUME_ITS_TRUE(fossil_ai_lang_is_question("Could you help me?"));
    ASSUME_ITS_TRUE(!fossil_ai_lang_is_question("This is not a question."));

    ASSUME_ITS_TRUE(Language::isQuestion("Is this a question?"));
    ASSUME_ITS_TRUE(Language::isQuestion("What time is it"));
    ASSUME_ITS_TRUE(!Language::isQuestion("This is not a question."));
}

FOSSIL_TEST_CASE(cpp_test_lang_detect_emotion) {
    float pos = fossil_ai_lang_detect_emotion("I love this!");
    float neg = fossil_ai_lang_detect_emotion("This is terrible.");
    float neu = fossil_ai_lang_detect_emotion("The sky is blue.");
    ASSUME_ITS_TRUE(pos > 0.5f);
    ASSUME_ITS_TRUE(neg < -0.5f);
    ASSUME_ITS_TRUE(neu > -0.2f && neu < 0.2f);

    ASSUME_ITS_TRUE(Language::detectEmotion("I love this!") > 0.5f);
}

FOSSIL_TEST_CASE(cpp_test_lang_detect_bias_or_falsehood) {
    ASSUME_ITS_EQUAL_I32(fossil_ai_lang_detect_bias_or_falsehood("Everyone knows this is the best!"), 1);
    ASSUME_ITS_EQUAL_I32(fossil_ai_lang_detect_bias_or_falsehood("The sun rises in the east."), 0);

    ASSUME_ITS_TRUE(Language::detectBiasOrFalsehood("Everyone knows this is the best!"));
    ASSUME_ITS_TRUE(!Language::detectBiasOrFalsehood("The sun rises in the east."));
}

FOSSIL_TEST_CASE(cpp_test_lang_align_truth) {
    fossil_ai_jellyfish_chain_t chain;
    fossil_ai_jellyfish_init(&chain);
    fossil_ai_iochat_learn_response(&chain, "The sky is blue.", "Yes, it is.");
    int aligned = fossil_ai_lang_align_truth(&chain, "The sky is blue.");
    int unknown = fossil_ai_lang_align_truth(&chain, "Grass is purple.");
    ASSUME_ITS_EQUAL_I32(aligned, 1);
    ASSUME_ITS_TRUE(unknown == 0 || unknown == -1);

    auto cppAligned = Language::alignTruth(&chain, "The sky is blue.");
    ASSUME_ITS_TRUE(cppAligned == Language::TruthAlignment::Aligned);
}

FOSSIL_TEST_CASE(cpp_test_lang_similarity) {
    float sim1 = fossil_ai_lang_similarity("The quick brown fox", "A quick brown fox");
    float sim2 = fossil_ai_lang_similarity("cat", "dog");
    float sim3 = fossil_ai_lang_similarity("identical", "identical");
    ASSUME_ITS_TRUE(sim1 > 0.5f);
    ASSUME_ITS_TRUE(sim2 < 0.5f);
    ASSUME_ITS_TRUE(sim3 > 0.99f);

    ASSUME_ITS_TRUE(Language::similarity("identical", "identical") > 0.99f);
}

FOSSIL_TEST_CASE(cpp_test_lang_summarize_and_normalize) {
    char summary[64] = {0};
    char normalized[64] = {0};
    fossil_ai_lang_summarize("This is a very long sentence that should be summarized.", summary, sizeof(summary));
    fossil_ai_lang_normalize("I'm gonna win!", normalized, sizeof(normalized));
    ASSUME_ITS_TRUE(strlen(summary) > 0);
    ASSUME_ITS_TRUE(strstr(normalized, "going to") != NULL);

    auto cppSummary = Language::summarize("This is a very long sentence that should be summarized.");
    auto cppNorm = Language::normalize("I'm gonna win!");
    ASSUME_ITS_TRUE(!cppSummary.empty());
    ASSUME_ITS_TRUE(cppNorm.find("going to") != std::string::npos);
}

FOSSIL_TEST_CASE(cpp_test_lang_extract_focus) {
    char focus[32] = {0};
    fossil_ai_lang_extract_focus("The quick brown fox jumps over the lazy dog.", focus, sizeof(focus));
    ASSUME_ITS_TRUE(strlen(focus) > 0);
    ASSUME_ITS_TRUE(strstr(focus, "fox") != NULL || strstr(focus, "dog") != NULL);

    auto cppFocus = Language::extractFocus("The quick brown fox jumps over the lazy dog.");
    ASSUME_ITS_TRUE(!cppFocus.empty());
}

FOSSIL_TEST_CASE(cpp_test_lang_estimate_trust) {
    fossil_ai_jellyfish_chain_t chain;
    fossil_ai_jellyfish_init(&chain);
    float trust1 = fossil_ai_lang_estimate_trust(&chain, "The sky is blue.");
    float trust2 = fossil_ai_lang_estimate_trust(&chain, "Everyone knows this is the best!");
    ASSUME_ITS_TRUE(trust1 > trust2);
    ASSUME_ITS_TRUE(trust1 >= 0.0f && trust1 <= 1.0f);

    float trustCpp = Language::estimateTrust(&chain, "The sky is blue.");
    ASSUME_ITS_TRUE(trustCpp >= 0.0f && trustCpp <= 1.0f);
}

FOSSIL_TEST_CASE(cpp_test_lang_embedding_similarity) {
    float a[4] = {1.0f, 0.0f, 0.0f, 0.0f};
    float b[4] = {1.0f, 0.0f, 0.0f, 0.0f};
    float c[4] = {0.0f, 1.0f, 0.0f, 0.0f};
    float sim_ab = fossil_ai_lang_embedding_similarity(a, b, 4);
    float sim_ac = fossil_ai_lang_embedding_similarity(a, c, 4);
    ASSUME_ITS_TRUE(sim_ab > 0.99f);
    ASSUME_ITS_TRUE(sim_ac < 0.1f);

    std::vector<float> va{1,0,0,0}, vb{1,0,0,0}, vc{0,1,0,0};
    ASSUME_ITS_TRUE(Language::embeddingSimilarity(va, vb) > 0.99f);
    ASSUME_ITS_TRUE(Language::embeddingSimilarity(va, vc) < 0.2f);

    bool threw = false;
    try {
        std::vector<float> sm{1.f};
        std::vector<float> lg{1.f, 2.f};
        (void)Language::embeddingSimilarity(sm, lg);
    } catch (const std::invalid_argument &) {
        threw = true;
    }
    ASSUME_ITS_TRUE(threw);
}

FOSSIL_TEST_CASE(cpp_test_lang_generate_variants) {
    char variants[3][256] = {{0}};
    fossil_ai_lang_generate_variants("hello", variants, 3);
    ASSUME_ITS_TRUE(strlen(variants[0]) > 0);
    ASSUME_ITS_TRUE(strcmp(variants[0], "hello") == 0 || strcmp(variants[1], "hello") == 0);

    auto cppVars = Language::generateVariants("hello", 3);
    ASSUME_ITS_TRUE(!cppVars.empty());
    ASSUME_ITS_TRUE(cppVars[0].find("hello") != std::string::npos);
}

FOSSIL_TEST_CASE(cpp_test_lang_process_pipeline) {
    fossil_ai_lang_pipeline_t pipe = {0};
    fossil_ai_lang_result_t result = {0};
    fossil_ai_lang_process(&pipe, "Is this a test?", &result);
    ASSUME_ITS_TRUE(result.token_count > 0 || result.is_question);

    Language::PipelineConfig cfg;
    auto full = Language::process(cfg, "Is this a test?");
    ASSUME_ITS_TRUE(full.tokens.size() > 0 || full.is_question);

    auto quick = Language::quickProcess("Some QUICK text!");
    ASSUME_ITS_TRUE(!quick.normalized.empty());
    ASSUME_ITS_TRUE(quick.tokens.size() > 0);
    ASSUME_ITS_TRUE(!quick.is_question); // quick disables question detection
}

/* Added tests for new Jellyfish commit / FSON model */

FOSSIL_TEST_CASE(cpp_test_jellyfish_commit_enum_values) {
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_UNKNOWN, 0);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_INIT, 1);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_BRANCH, 10);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_TAG, 20);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_EXPERIMENT, 30);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_SYNC, 40);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_DETACHED, 50);
    ASSUME_ITS_EQUAL_I32(JELLY_COMMIT_FINAL, 54);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_block_default_init) {
    fossil_ai_jellyfish_block_t blk = {0};
    ASSUME_ITS_EQUAL_I32(blk.block_type, JELLY_COMMIT_UNKNOWN);
    ASSUME_ITS_EQUAL_I32(blk.identity.parent_count, 0);
    ASSUME_ITS_TRUE(blk.io.input_len == 0 && blk.io.output_len == 0);
}

FOSSIL_TEST_CASE(cpp_test_jellyfish_chain_basicpp_init) {
    fossil_ai_jellyfish_chain_t chain = {0};
    ASSUME_ITS_EQUAL_I32(chain.count, 0);
    ASSUME_ITS_TRUE(chain.branch_count == 0);
}

// * * * * * * * * * * * * * * * * * * * * * * * *
// * Fossil Logic Test Pool
// * * * * * * * * * * * * * * * * * * * * * * * *
FOSSIL_TEST_GROUP(cpp_lang_tests) {
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_tokenize_basic);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_is_question);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_detect_emotion);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_detect_bias_or_falsehood);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_align_truth);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_similarity);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_summarize_and_normalize);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_extract_focus);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_estimate_trust);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_embedding_similarity);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_generate_variants);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_lang_process_pipeline);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_jellyfish_commit_enum_values);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_jellyfish_block_default_init);
    FOSSIL_TEST_ADD(cpp_lang_fixture, cpp_test_jellyfish_chain_basicpp_init);

    FOSSIL_TEST_REGISTER(cpp_lang_fixture);
} // end of tests
