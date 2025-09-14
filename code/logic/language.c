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
#include "fossil/ai/language.h"


void fossil_lang_process(const fossil_lang_pipeline_t *pipe, const char *input, fossil_lang_result_t *out) {
    char working[FOSSIL_LANG_PIPELINE_OUTPUT_SIZE] = {0};
    const char *src = input;

    if (pipe->normalize) {
        fossil_lang_normalize(input, working, sizeof(working));
        src = working;
    
        // Safe copy with guaranteed null-termination
        snprintf(out->normalized, sizeof(out->normalized), "%s", working);
    }

    if (pipe->tokenize) {
        out->token_count = fossil_lang_tokenize(src, out->tokens, 64);
    }

    if (pipe->detect_emotion) {
        out->emotion_score = fossil_lang_detect_emotion(src);
    }

    if (pipe->detect_bias) {
        out->bias_detected = fossil_lang_detect_bias_or_falsehood(src);
    }

    if (pipe->is_question) {
        out->is_question = fossil_lang_is_question(src);
    }

    if (pipe->extract_focus) {
        fossil_lang_extract_focus(src, out->focus, sizeof(out->focus));
    }

    if (pipe->summarize) {
        fossil_lang_summarize(src, out->summary, sizeof(out->summary));
    }
}

size_t fossil_lang_tokenize(const char *input, char tokens[][FOSSIL_JELLYFISH_TOKEN_SIZE], size_t max_tokens) {
    size_t count = 0, len = strlen(input);
    char word[FOSSIL_JELLYFISH_TOKEN_SIZE] = {0};
    size_t wi = 0;

    for (size_t i = 0; i <= len; ++i) {
        char c = input[i];
        if (isalnum((unsigned char)c)) {
            if (wi < FOSSIL_JELLYFISH_TOKEN_SIZE - 1)
                word[wi++] = tolower((unsigned char)c);
        } else {
            if (wi > 0 && count < max_tokens) {
                word[wi] = '\0';
                strncpy(tokens[count++], word, FOSSIL_JELLYFISH_TOKEN_SIZE);
                wi = 0;
            }
        }
    }
    return count;
}

bool fossil_lang_is_question(const char *input) {
    size_t len = strlen(input);
    if (len == 0) return false;

    if (input[len - 1] == '?') return true;

    const char *wh[] = {
        "what", "why", "how", "who", "when", "where", "is", "are", "do", "does", "can",
        "could", "would", "should", "will", "did", "may", "might", "shall", "whose", "whom",
        "which", "was", "were", "has", "have", "had", "am"
    };
    char first[16] = {0};

    sscanf(input, "%15s", first);
    for (int i = 0; first[i]; ++i) first[i] = tolower(first[i]);

    for (size_t i = 0; i < sizeof(wh) / sizeof(wh[0]); ++i)
        if (strcmp(first, wh[i]) == 0)
            return true;

    return false;
}

float fossil_lang_detect_emotion(const char *input) {
    const char *positive[] = {
        "great", "love", "happy", "good", "excellent", "amazing", "yes", "awesome", "fantastic", "wonderful",
        "positive", "joy", "joyful", "delight", "delighted", "pleased", "satisfied", "brilliant", "superb",
        "outstanding", "cheerful", "smile", "smiling", "success", "successful", "win", "winning", "enjoy",
        "enjoyed", "enjoying", "like", "liked", "likes", "best", "cool", "nice", "grateful", "thankful",
        "optimistic", "hopeful", "enthusiastic", "encouraged", "motivated", "inspired", "peaceful", "calm"
    };
    const char *negative[] = {
        "hate", "bad", "sad", "angry", "terrible", "no", "awful", "horrible", "worst", "negative", "pain",
        "painful", "disappointed", "disappointing", "failure", "fail", "loser", "lose", "losing", "cry",
        "crying", "depressed", "upset", "mad", "furious", "annoyed", "frustrated", "dislike", "disliked",
        "disgust", "disgusted", "unhappy", "miserable", "hopeless", "pessimistic", "resentful", "bitter",
        "jealous", "regret", "ashamed", "guilty", "afraid", "scared", "fear", "anxious", "nervous"
    };

    float score = 0.0f;
    char tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
    size_t n = fossil_lang_tokenize(input, tokens, FOSSIL_JELLYFISH_MAX_TOKENS);

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0; j < sizeof(positive) / sizeof(positive[0]); ++j)
            if (strcmp(tokens[i], positive[j]) == 0) score += 1.0f;
        for (size_t j = 0; j < sizeof(negative) / sizeof(negative[0]); ++j)
            if (strcmp(tokens[i], negative[j]) == 0) score -= 1.0f;
    }

    if (score > 3.0f) score = 3.0f;
    if (score < -3.0f) score = -3.0f;
    return score / 3.0f; // Normalize to [-1.0, 1.0]
}

int fossil_lang_detect_bias_or_falsehood(const char *input) {
    const char *bias_phrases[] = {
        "everyone knows", "obviously", "literally", "always", "never", "the truth is",
        "you have to believe", "no one can deny", "it's a fact", "fake news",
        "clearly", "undeniably", "without a doubt", "as we all know", "it is certain",
        "all the experts agree", "it goes without saying", "as everyone agrees",
        "the only explanation", "there is no alternative", "must be true",
        "cannot be false", "beyond question", "no one disagrees", "it is proven",
        "everybody says", "it is obvious", "as is well known", "it is well established",
        "the fact remains", "the reality is", "it is clear", "it is evident",
        "the simple truth", "the undeniable fact", "the only possible", "it is universally accepted"
    };

    for (size_t i = 0; i < sizeof(bias_phrases) / sizeof(bias_phrases[0]); ++i) {
        if (strstr(input, bias_phrases[i]) != NULL) return 1;
    }

    return 0;
}

int fossil_lang_align_truth(const fossil_jellyfish_chain_t *chain, const char *input) {
    if (!chain || !input) return 0;

    for (size_t i = 0; i < chain->count; ++i) {
        const fossil_jellyfish_block_t *b = &chain->memory[i];
        if (!b->attributes.valid) continue;

        if (strcmp(input, b->io.input) == 0) {
            if (strcmp(b->io.output, "false") == 0 || strcmp(b->io.output, "incorrect") == 0)
                return -1;
            return 1;
        }
    }

    return 0;
}

float fossil_lang_estimate_trust(const fossil_jellyfish_chain_t *chain, const char *input) {
    if (!input || strlen(input) < 3) return 0.1f;

    int contradiction = fossil_lang_align_truth(chain, input);
    if (contradiction < 0) return 0.0f;

    float emotion = fossil_lang_detect_emotion(input);
    float bias = fossil_lang_detect_bias_or_falsehood(input) ? -0.5f : 0.0f;

    float trust = 0.5f + (emotion * 0.25f) + (bias);
    if (trust > 1.0f) trust = 1.0f;
    if (trust < 0.0f) trust = 0.0f;

    return trust;
}

void fossil_lang_normalize(const char *input, char *out, size_t out_size) {
    struct {
        const char *slang;
        const char *formal;
    } replacements[] = {
        {"gonna", "going to"},
        {"wanna", "want to"},
        {"gotta", "have to"},
        {"ain't", "is not"},
        {"can't", "cannot"},
        {"don't", "do not"},
        {"won't", "will not"},
        {"y'all", "you all"},
        {"lemme", "let me"},
        {"gimme", "give me"},
        {"cuz", "because"},
        {"u", "you"},
        {"r", "are"},
        {"ur", "your"},
        {"im", "I am"},
        {"idk", "I don't know"},
        {"lol", "(laughing)"},
        {"btw", "by the way"},
        {"brb", "be right back"},
        {"omg", "oh my god"},
        {"thx", "thanks"},
        {"pls", "please"},
        {"plz", "please"},
        {"b4", "before"},
        {"gr8", "great"},
        {"lmk", "let me know"},
        {"np", "no problem"},
        {"tbh", "to be honest"},
        {"afaik", "as far as I know"},
        {"asap", "as soon as possible"},
        {"fyi", "for your information"},
        {"smh", "shaking my head"},
        {"tldr", "too long; didn't read"},
        {"bff", "best friend forever"},
        {"jk", "just kidding"},
        {"nvm", "never mind"},
        {"rofl", "rolling on the floor laughing"},
        {"ttyl", "talk to you later"},
        {"wyd", "what are you doing"},
        {"wbu", "what about you"},
        {"irl", "in real life"},
        {"dm", "direct message"},
        {"imo", "in my opinion"},
        {"imho", "in my humble opinion"},
        {"ftw", "for the win"},
        {"gg", "good game"},
        {"afk", "away from keyboard"},
        {"bc", "because"},
        {"tho", "though"},
        {"sup", "what's up"},
        {"ya", "you"},
        {"tho", "though"},
        {"msg", "message"},
        {"pic", "picture"},
        {"pics", "pictures"}
    };

    const char *p = input;
    char token[64] = {0};
    size_t out_len = 0;

    while (*p && out_len < out_size - 1) {
        size_t t = 0;
        while (*p && !isspace(*p) && t < sizeof(token) - 1)
            token[t++] = tolower(*p++);
        token[t] = '\0';

        const char *replacement = NULL;
        for (size_t i = 0; i < sizeof(replacements) / sizeof(replacements[0]); ++i) {
            if (strcmp(token, replacements[i].slang) == 0) {
                replacement = replacements[i].formal;
                break;
            }
        }

        const char *word = replacement ? replacement : token;
        size_t wlen = strlen(word);
        if (out_len + wlen >= out_size - 1) break;

        memcpy(out + out_len, word, wlen);
        out_len += wlen;

        if (*p && out_len < out_size - 1) {
            out[out_len++] = ' ';
            while (isspace(*p)) ++p;
        }
    }

    if (out_len > 0 && out[out_len - 1] == ' ') --out_len;
    out[out_len] = '\0';
}

void fossil_lang_summarize(const char *input, char *out, size_t out_size) {
    char tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
    size_t token_count = fossil_lang_tokenize(input, tokens, FOSSIL_JELLYFISH_MAX_TOKENS);

    size_t out_len = 0;
    for (size_t i = 0; i < token_count && out_len < out_size - 1; ++i) {
        const char *tok = tokens[i];
        size_t len = strlen(tok);
        if (out_len + len + 1 >= out_size) break;

        if (i > 0) out[out_len++] = ' ';
        memcpy(out + out_len, tok, len);
        out_len += len;
    }

    out[out_len] = '\0';
}

void fossil_lang_extract_focus(const char *input, char *out, size_t out_size) {
    const char *stopwords[] = {
        "i", "you", "we", "they", "he", "she", "it",
        "me", "my", "mine", "your", "yours", "our", "ours", "their", "theirs", "his", "her", "hers", "its",
        "am", "is", "are", "was", "were", "be", "been", "being",
        "do", "does", "did", "doing", "will", "can", "should", "would", "could", "may", "might", "must", "shall",
        "have", "has", "had", "having",
        "to", "a", "an", "the", "and", "or", "but", "if", "then", "else", "in", "on", "for", "with", "about", "against",
        "this", "that", "these", "those", "of", "at", "as", "from", "by", "so", "such", "than", "too", "very", "just",
        "not", "no", "nor", "yet", "also", "because", "while", "where", "when", "which", "who", "whom", "whose", "what",
        "how", "why", "all", "any", "both", "each", "few", "more", "most", "other", "some", "such", "only", "own", "same",
        "over", "under", "again", "further", "once", "here", "there", "out", "up", "down", "off", "above", "below", "into",
        "between", "through", "during", "before", "after", "around", "among"
    };

    char tokens[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
    size_t count = fossil_lang_tokenize(input, tokens, FOSSIL_JELLYFISH_MAX_TOKENS);

    for (size_t i = 0; i < count; ++i) {
        int skip = 0;
        for (size_t j = 0; j < sizeof(stopwords) / sizeof(stopwords[0]); ++j) {
            if (strcmp(tokens[i], stopwords[j]) == 0) {
                skip = 1;
                break;
            }
        }

        if (!skip) {
            strncpy(out, tokens[i], out_size - 1);
            out[out_size - 1] = '\0';
            return;
        }
    }

    // fallback
    strncpy(out, count > 0 ? tokens[0] : "", out_size - 1);
    out[out_size - 1] = '\0';
}

float fossil_lang_similarity(const char *a, const char *b) {
    char tokens_a[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];
    char tokens_b[FOSSIL_JELLYFISH_MAX_TOKENS][FOSSIL_JELLYFISH_TOKEN_SIZE];

    size_t count_a = fossil_lang_tokenize(a, tokens_a, FOSSIL_JELLYFISH_MAX_TOKENS);
    size_t count_b = fossil_lang_tokenize(b, tokens_b, FOSSIL_JELLYFISH_MAX_TOKENS);

    size_t match = 0;
    for (size_t i = 0; i < count_a; ++i) {
        for (size_t j = 0; j < count_b; ++j) {
            if (strcmp(tokens_a[i], tokens_b[j]) == 0) {
                ++match;
                break;
            }
        }
    }

    size_t total = count_a + count_b;
    if (total == 0) return 0.0f;

    return (2.0f * match) / total; // Jaccard-based estimate
}

void fossil_lang_trace_log(const char *category, const char *input, float score) {
    fprintf(stderr, "[NLP-TRACE] [%s] Score=%.3f | Input=\"%s\"\n", category, score, input);
}

float fossil_lang_embedding_similarity(const float *vec_a, const float *vec_b, size_t len) {
    float dot = 0.0f, norm_a = 0.0f, norm_b = 0.0f;

    for (size_t i = 0; i < len; ++i) {
        dot += vec_a[i] * vec_b[i];
        norm_a += vec_a[i] * vec_a[i];
        norm_b += vec_b[i] * vec_b[i];
    }

    if (norm_a == 0.0f || norm_b == 0.0f) return 0.0f;
    return dot / (sqrtf(norm_a) * sqrtf(norm_b));
}

typedef struct {
    const char *word;
    const char *alt;
} synonym_pair;

static const synonym_pair replacements[] = {
    {"great", "excellent"},
    {"happy", "joyful"},
    {"sad", "unhappy"},
    {"angry", "mad"},
    {"love", "adore"},
    {"hate", "dislike"},
    {"good", "nice"},
    {"bad", "poor"},
    {"fast", "quick"},
    {"slow", "sluggish"},
    {"smart", "intelligent"},
    {"dumb", "unintelligent"},
    {"easy", "simple"},
    {"hard", "difficult"},
    {"big", "large"},
    {"small", "tiny"},
    {"old", "ancient"},
    {"young", "youthful"},
    {"strong", "powerful"},
    {"weak", "frail"},
    {"rich", "wealthy"},
    {"poor", "destitute"},
    {"clean", "spotless"},
    {"dirty", "filthy"},
    {"funny", "humorous"},
    {"serious", "grave"},
    {"quick", "rapid"},
    {"slow", "lethargic"},
    {"beautiful", "gorgeous"},
    {"ugly", "unattractive"},
    {"friendly", "amiable"},
    {"mean", "cruel"},
    {"hot", "warm"},
    {"cold", "chilly"},
    {"bright", "luminous"},
    {"dark", "dim"},
    {"easy", "effortless"},
    {"difficult", "challenging"},
    {"important", "crucial"},
    {"unimportant", "trivial"},
    {"safe", "secure"},
    {"dangerous", "hazardous"}
};

void fossil_lang_generate_variants(const char *input, char outputs[][256], size_t max_outputs) {
    size_t count = 0;

    for (size_t i = 0; i < sizeof(replacements) / sizeof(replacements[0]); ++i) {
        if (strstr(input, replacements[i].word) != NULL && count < max_outputs) {
            char buf[256];
            strncpy(buf, input, sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';

            char *pos = strstr(buf, replacements[i].word);
            if (pos) {
                size_t prefix = pos - buf;
                snprintf(outputs[count], 256, "%.*s%s%s",
                         (int)prefix,
                         buf,
                         replacements[i].alt,
                         pos + strlen(replacements[i].word));
                ++count;
            }
        }
    }

    if (count == 0 && max_outputs > 0) {
        strncpy(outputs[0], input, 255);
        outputs[0][255] = '\0';
    }
}
