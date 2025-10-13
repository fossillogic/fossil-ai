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
#ifndef FOSSIL_JELLYFISH_LANG_H
#define FOSSIL_JELLYFISH_LANG_H

#include "jellyfish.h"

#define fossil_ai_lang_PIPELINE_OUTPUT_SIZE 1024

#ifndef FOSSIL_JELLYFISH_TOKEN_SIZE
#define FOSSIL_JELLYFISH_TOKEN_SIZE 32
#endif

#ifndef FOSSIL_JELLYFISH_MAX_TOKENS
#define FOSSIL_JELLYFISH_MAX_TOKENS 64
#endif

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct {
    bool normalize;
    bool tokenize;
    bool detect_emotion;
    bool detect_bias;
    bool extract_focus;
    bool is_question;
    bool summarize;
} fossil_ai_lang_pipeline_t;

typedef struct {
    float emotion_score;
    bool bias_detected;
    bool is_question;
    char focus[64];
    char summary[fossil_ai_lang_PIPELINE_OUTPUT_SIZE];
    char normalized[fossil_ai_lang_PIPELINE_OUTPUT_SIZE];
    char tokens[64][FOSSIL_JELLYFISH_TOKEN_SIZE];
    size_t token_count;
} fossil_ai_lang_result_t;

// *****************************************************************************
// Function prototypes
// *****************************************************************************

/**
 * Tokenizes input into normalized lowercase tokens.
 * Removes punctuation and collapses whitespace.
 */
size_t fossil_ai_lang_tokenize(const char *input, char tokens[][FOSSIL_JELLYFISH_TOKEN_SIZE], size_t max_tokens);

/**
 * Determines whether a given input is a question.
 * Looks for terminal punctuation and question phrases.
 */
bool fossil_ai_lang_is_question(const char *input);

/**
 * Guesses the emotional tone of a sentence.
 * Returns a score (-1.0 sad → 0.0 neutral → +1.0 positive).
 */
float fossil_ai_lang_detect_emotion(const char *input);

/**
 * Attempts to identify bias, exaggeration, or unverified claims in input.
 * Returns 1 if detected, 0 if not.
 */
int fossil_ai_lang_detect_bias_or_falsehood(const char *input);

/**
 * Performs truth alignment by comparing input to known chain knowledge.
 * Returns:
 *   1  → consistent/truth-aligned
 *   0  → unknown
 *  -1  → contradiction detected
 */
int fossil_ai_lang_align_truth(const fossil_ai_jellyfish_chain_t *chain, const char *input);

/**
 * Computes semantic similarity between two input strings.
 * Returns a float between 0.0 (no match) to 1.0 (identical meaning).
 */
float fossil_ai_lang_similarity(const char *a, const char *b);

/**
 * Generates a compressed summary of the input string.
 * Result written to `out`, which must be preallocated.
 */
void fossil_ai_lang_summarize(const char *input, char *out, size_t out_size);

/**
 * Attempts to normalize slang, contractions, or informal expressions.
 * Output is written to `out`, which must be preallocated.
 */
void fossil_ai_lang_normalize(const char *input, char *out, size_t out_size);

/**
 * Extracts the most meaningful phrase from input for matching.
 * Good for chaining to Jellyfish reasoning.
 */
void fossil_ai_lang_extract_focus(const char *input, char *out, size_t out_size);

/**
 * Estimates trustworthiness of the input text based on
 * structure, word choice, exaggeration, and alignment.
 * Score is in [0.0, 1.0].
 */
float fossil_ai_lang_estimate_trust(const fossil_ai_jellyfish_chain_t *chain, const char *input);

/**
 * Replace slang and contractions with formal equivalents.
 * This is a fixed-rule version (extendable).
 */
void fossil_ai_lang_normalize(const char *input, char *out, size_t out_size);

/**
 * Extracts key content from the first few meaningful tokens.
 * Simple lead-based summarization.
 */
void fossil_ai_lang_summarize(const char *input, char *out, size_t out_size);

/**
 * Extracts a "focus word" — usually a noun or key concept — from the input.
 * Current version uses simple heuristics and common stopwords.
 */
void fossil_ai_lang_extract_focus(const char *input, char *out, size_t out_size);

/**
 * Simple bag-of-words overlap similarity between two strings.
 * Returns a float between 0.0 (no overlap) and 1.0 (identical sets).
 */
float fossil_ai_lang_similarity(const char *a, const char *b);

/**
 * Processes input through a pipeline of NLP tasks.
 * Each task can be enabled/disabled via the pipeline configuration.
 */
void fossil_ai_lang_process(const fossil_ai_lang_pipeline_t *pipe, const char *input, fossil_ai_lang_result_t *out);

/**
 * Logs a trace message for NLP processing.
 * Useful for debugging and performance analysis.
 */
void fossil_ai_lang_trace_log(const char *category, const char *input, float score);

/**
 * Computes cosine similarity between two embedding vectors.
 * Returns a float between 0.0 (orthogonal) and 1.0 (identical).
 */
float fossil_ai_lang_embedding_similarity(const float *vec_a, const float *vec_b, size_t len);

/**
 * Generates alternative phrasings for a given input.
 * Useful for expanding search queries or generating variants.
 * Outputs are written to `outputs`, which must be preallocated.
 */
void fossil_ai_lang_generate_variants(const char *input, char outputs[][256], size_t max_outputs);

#ifdef __cplusplus
}
#include <stdexcept>
#include <memory>
#include <vector>
#include <string>
#include <array>

namespace fossil {

    namespace ai {

        
        /**
         * @brief High-level C++ wrapper for the Fossil language processing C API.
         *
         * Provides safer, RAII-friendly, STL-integrated helpers that delegate to the
         * low-level fossil_ai_lang_* C functions. Designed for light-weight usage with
         * zero persistent heap allocations beyond returned STL containers.
         *
         * Thread-safety: All static functions are reentrant PROVIDED the underlying
         * C implementations are reentrant. No internal static mutable state here.
         */
        class Language {
        public:
            // ---------------------------------------------------------------------
            // Core compile-time constants mirroring C definitions
            // ---------------------------------------------------------------------
            static constexpr size_t TokenSize      = FOSSIL_JELLYFISH_TOKEN_SIZE;   ///< Size of each individual token buffer (chars).
            static constexpr size_t MaxTokens      = FOSSIL_JELLYFISH_MAX_TOKENS;   ///< Maximum number of tokens produced by tokenizer.
            static constexpr size_t PipelineBufLen = fossil_ai_lang_PIPELINE_OUTPUT_SIZE; ///< Shared buffer size for summary/normalize/focus.
            static constexpr size_t VariantBufSize = 256;                           ///< Fixed buffer length per generated variant.

            /**
             * @brief Enum mapping for truth alignment outcomes.
             *
             * Matches fossil_ai_lang_align_truth return codes for type safety and clarity.
             */
            enum class TruthAlignment : int {
                Contradiction = -1, ///< Input contradicts known chain knowledge.
                Unknown       = 0,  ///< No decisive match / insufficient evidence.
                Aligned       = 1   ///< Consistent with existing knowledge.
            };

            /**
             * @brief Configuration object for multi-stage language pipeline execution.
             *
             * Each flag toggles a feature inside fossil_ai_lang_process. Defaults enable
             * all stages. Convert to C struct via to_c().
             */
            struct PipelineConfig {
                bool normalize      = true; ///< Perform slang/contraction normalization.
                bool tokenize       = true; ///< Produce token sequence.
                bool detect_emotion = true; ///< Compute coarse emotional valence.
                bool detect_bias    = true; ///< Flag potential bias / exaggeration.
                bool extract_focus  = true; ///< Extract salient focus term.
                bool is_question    = true; ///< Identify interrogative form.
                bool summarize      = true; ///< Produce short extractive summary.

                /**
                 * @brief Convert to underlying C API structure.
                 */
                fossil_ai_lang_pipeline_t to_c() const {
                    fossil_ai_lang_pipeline_t p{
                        normalize,
                        tokenize,
                        detect_emotion,
                        detect_bias,
                        extract_focus,
                        is_question,
                        summarize
                    };
                    return p;
                }
            };

            /**
             * @brief Result container for pipeline execution.
             *
             * Owns STL strings and vector of tokens translated from fossil_ai_lang_result_t.
             */
            struct Result {
                float emotion_score = 0.f;             ///< -1..+1 emotional valence.
                bool  bias_detected = false;           ///< True if heuristic bias flagged.
                bool  is_question   = false;           ///< True if input classified as question.
                std::string focus;                     ///< Extracted focus word/phrase.
                std::string summary;                   ///< Generated summary (may be truncated).
                std::string normalized;                ///< Normalized form (if enabled).
                std::vector<std::string> tokens;       ///< Token list (if enabled).

                /**
                 * @brief Translate from C struct into STL-friendly object.
                 */
                static Result from_c(const fossil_ai_lang_result_t &cres) {
                    Result r;
                    r.emotion_score = cres.emotion_score;
                    r.bias_detected = cres.bias_detected;
                    r.is_question   = cres.is_question;
                    r.focus         = cres.focus;
                    r.summary       = cres.summary;
                    r.normalized    = cres.normalized;
                    r.tokens.reserve(cres.token_count);
                    for (size_t i = 0; i < cres.token_count; ++i) {
                        r.tokens.emplace_back(cres.tokens[i]);
                    }
                    return r;
                }
            };

            /**
             * @brief Tokenize text into lowercase normalized tokens.
             * @return Vector of tokens (size <= MaxTokens).
             */
            static std::vector<std::string> tokenize(const std::string &text) {
                char raw[MaxTokens][TokenSize] = {};
                size_t count = fossil_ai_lang_tokenize(text.c_str(), raw, MaxTokens);
                std::vector<std::string> out;
                out.reserve(count);
                for (size_t i = 0; i < count; ++i) out.emplace_back(raw[i]);
                return out;
            }

            /**
             * @brief Check if text appears to be a question.
             */
            static bool isQuestion(const std::string &text) {
                return fossil_ai_lang_is_question(text.c_str());
            }

            /**
             * @brief Estimate emotional polarity.
             */
            static float detectEmotion(const std::string &text) {
                return fossil_ai_lang_detect_emotion(text.c_str());
            }

            /**
             * @brief Heuristic detection of bias / falsehood cues.
             */
            static bool detectBiasOrFalsehood(const std::string &text) {
                return fossil_ai_lang_detect_bias_or_falsehood(text.c_str()) != 0;
            }

            /**
             * @brief Align statement with chain knowledge base.
             */
            static TruthAlignment alignTruth(const fossil_ai_jellyfish_chain_t *chain,
                                            const std::string &text) {
                return static_cast<TruthAlignment>(
                    fossil_ai_lang_align_truth(chain, text.c_str()));
            }

            /**
             * @brief Simple bag-of-words similarity.
             */
            static float similarity(const std::string &a, const std::string &b) {
                return fossil_ai_lang_similarity(a.c_str(), b.c_str());
            }

            /**
             * @brief Generate short summary (extractive).
             */
            static std::string summarize(const std::string &text) {
                char buf[PipelineBufLen] = {};
                fossil_ai_lang_summarize(text.c_str(), buf, sizeof(buf));
                return std::string(buf);
            }

            /**
             * @brief Normalize slang / contractions.
             */
            static std::string normalize(const std::string &text) {
                char buf[PipelineBufLen] = {};
                fossil_ai_lang_normalize(text.c_str(), buf, sizeof(buf));
                return std::string(buf);
            }

            /**
             * @brief Extract salient focus term/phrase.
             */
            static std::string extractFocus(const std::string &text) {
                char buf[PipelineBufLen] = {};
                fossil_ai_lang_extract_focus(text.c_str(), buf, sizeof(buf));
                return std::string(buf);
            }

            /**
             * @brief Composite trustworthiness estimation.
             */
            static float estimateTrust(const fossil_ai_jellyfish_chain_t *chain,
                                    const std::string &text) {
                return fossil_ai_lang_estimate_trust(chain, text.c_str());
            }

            /**
             * @brief Emit trace diagnostic log.
             */
            static void traceLog(const std::string &category,
                                const std::string &input,
                                float score) {
                fossil_ai_lang_trace_log(category.c_str(), input.c_str(), score);
            }

            /**
             * @brief Cosine similarity over embedding vectors.
             * @throws std::invalid_argument size mismatch.
             */
            static float embeddingSimilarity(const std::vector<float> &a,
                                            const std::vector<float> &b) {
                if (a.size() != b.size())
                    throw std::invalid_argument("embedding size mismatch");
                return fossil_ai_lang_embedding_similarity(a.data(), b.data(), a.size());
            }

            /**
             * @brief Generate paraphrased / alternate phrasings.
             * Stops early on first empty variant.
             */
            static std::vector<std::string> generateVariants(const std::string &text,
                                                            size_t max_outputs = 8) {
                if (max_outputs == 0) return {};
                std::unique_ptr<char[]> flat(new char[max_outputs * VariantBufSize]());
                auto at = [&](size_t i)->char* { return flat.get() + i * VariantBufSize; };
                fossil_ai_lang_generate_variants(text.c_str(),
                                            reinterpret_cast<char (*)[VariantBufSize]>(flat.get()),
                                            max_outputs);
                std::vector<std::string> result;
                for (size_t i = 0; i < max_outputs; ++i) {
                    if (at(i)[0] == '\0') break;
                    result.emplace_back(at(i));
                }
                return result;
            }

            /**
             * @brief Run configurable multi-stage pipeline.
             */
            static Result process(const PipelineConfig &cfg,
                                const std::string &text) {
                fossil_ai_lang_pipeline_t p = cfg.to_c();
                fossil_ai_lang_result_t cres{};
                fossil_ai_lang_process(&p, text.c_str(), &cres);
                return Result::from_c(cres);
            }

            /**
             * @brief Convenience minimal processing (normalize + tokenize).
             */
            static Result quickProcess(const std::string &text) {
                PipelineConfig cfg;
                cfg.detect_bias = false;
                cfg.detect_emotion = false;
                cfg.extract_focus = false;
                cfg.is_question = false;
                cfg.summarize = false;
                return process(cfg, text);
            }
        };
        
    } // namespace ai

} // namespace fossil

#endif

#endif /* fossil_fish_FRAMEWORK_H */
