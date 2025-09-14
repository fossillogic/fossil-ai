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
#ifndef FOSSIL_JELLYFISH_IOCHAT_H
#define FOSSIL_JELLYFISH_IOCHAT_H

#include "jellyfish.h"

#ifdef __cplusplus
extern "C"
{
#endif

// *****************************************************************************
// Function prototypes
// *****************************************************************************

/**
 * @brief Starts a new conversation session.
 *
 * Initializes a context for handling multi-turn dialogue.
 *
 * @param context_name Optional name for the context/session.
 * @return 0 on success, non-zero on failure.
 */
int fossil_io_chat_start(const char *context_name, fossil_jellyfish_chain_t *chain);

/**
 * @brief Processes a user input and generates a chatbot response.
 *
 * Leverages the Jellyfish memory chain to reason about the input.
 *
 * @param chain   Pointer to Jellyfish chain.
 * @param input   User input string.
 * @param output  Output buffer to receive response.
 * @param size    Size of output buffer.
 * @return        0 if response found, -1 if unknown.
 */
int fossil_io_chat_respond(fossil_jellyfish_chain_t *chain, const char *input, char *output, size_t size);

/**
 * @brief Ends the current conversation session and performs cleanup.
 *
 * Frees temporary memory, flushes session logs, or persists updates.
 *
 * @return 0 on success.
 */
int fossil_io_chat_end(fossil_jellyfish_chain_t *chain);

/**
 * @brief Injects a system message into the chain (e.g. "Hello", "System Ready").
 *
 * System messages are logged as immutable memory blocks with device signature.
 *
 * @param chain  Jellyfish chain.
 * @param message System-level message.
 * @return 0 on success.
 */
int fossil_io_chat_inject_system_message(fossil_jellyfish_chain_t *chain, const char *message);

/**
 * @brief Appends a chatbot-generated response to the chain memory.
 *
 * Treats this as a new output associated with the latest user input.
 *
 * @param chain   Chain to add memory to.
 * @param input   Original user input.
 * @param output  Chatbot response to learn.
 * @return 0 on success.
 */
int fossil_io_chat_learn_response(fossil_jellyfish_chain_t *chain, const char *input, const char *output);

/**
 * @brief Returns the number of conversational turns remembered.
 *
 * @param chain Jellyfish chain.
 * @return Number of user-input/output pairs.
 */
int fossil_io_chat_turn_count(const fossil_jellyfish_chain_t *chain);

/**
 * @brief Summarizes the session into a concise text form.
 *
 * This scans the chat blocks and returns a summary paragraph based on user turns.
 *
 * @param chain     Jellyfish chain to summarize.
 * @param summary   Output buffer to store summary.
 * @param size      Size of the output buffer.
 * @return 0 on success, -1 if summary couldn't be generated.
 */
int fossil_io_chat_summarize_session(const fossil_jellyfish_chain_t *chain, char *summary, size_t size);

/**
 * @brief Filters the most recent N turns into a temporary sub-chain.
 *
 * Useful for generating context-limited decisions.
 *
 * @param chain     Original chat chain.
 * @param out_chain Output chain filled with most recent turns.
 * @param turn_count Number of recent user turns to include.
 * @return 0 on success.
 */
int fossil_io_chat_filter_recent(const fossil_jellyfish_chain_t *chain, fossil_jellyfish_chain_t *out_chain, int turn_count);

/**
 * @brief Exports the current conversation history to a text file.
 *
 * @param chain     Chain to serialize.
 * @param filepath  Destination path for output.
 * @return 0 on success, -1 on error.
 */
int fossil_io_chat_export_history(const fossil_jellyfish_chain_t *chain, const char *filepath);

/**
 * @brief Imports a context file and loads it into the chain.
 *
 * Useful for bootstrapping or restoring previous sessions.
 *
 * @param chain     Destination Jellyfish chain.
 * @param filepath  Source path of saved context.
 * @return 0 on success, -1 if parsing fails.
 */
int fossil_io_chat_import_context(fossil_jellyfish_chain_t *chain, const char *filepath);

#ifdef __cplusplus
}
#include <stdexcept>
#include <vector>
#include <string>

namespace fossil {

namespace ai {

    class IOChat {
    public:
        /**
         * @brief Starts a new conversation session.
         * 
         * Initializes a context for handling multi-turn dialogue.
         * 
         * @param context_name Optional name for the context/session.
         * @return 0 on success, non-zero on failure.
         */
        static int start(const char *context_name, fossil_jellyfish_chain_t *chain) {
            return fossil_io_chat_start(context_name, chain);
        }

        /**
         * @brief Processes a user input and generates a chatbot response.
         * 
         * Leverages the Jellyfish memory chain to reason about the input.
         * 
         * @param input User input string.
         * @param output Output buffer to receive response.
         * @param size Size of output buffer.
         * @return 0 if response found, -1 if unknown.
         */
        static int respond(fossil_jellyfish_chain_t *chain, const char *input, char *output, size_t size) {
            return fossil_io_chat_respond(chain, input, output, size);
        }

        /**
         * @brief Ends the current conversation session and performs cleanup.
         * 
         * Frees temporary memory, flushes session logs, or persists updates.
         * 
         * @return 0 on success.
         */
        static int end(fossil_jellyfish_chain_t *chain) {
            return fossil_io_chat_end(chain);
        }

        /**
         * @brief Injects a system message into the chain (e.g. "Hello", "System Ready").
         * 
         * System messages are logged as immutable memory blocks with device signature.
         * 
         * @param message System-level message.
         * @return 0 on success.
         */
        static int inject_system_message(fossil_jellyfish_chain_t *chain, const char *message) {
            return fossil_io_chat_inject_system_message(chain, message);
        }

        /**
         * @brief Learns a new response based on user input and chatbot output.
         * 
         * Updates the Jellyfish memory chain with the new information.
         * 
         * @param input User input string.
         * @param output Chatbot output string.
         * @return 0 on success, -1 on error.
         */
        static int learn_response(fossil_jellyfish_chain_t *chain, const char *input, const char *output) {
            return fossil_io_chat_learn_response(chain, input, output);
        }

        /**
         * @brief Returns the number of conversational turns remembered.
         * 
         * @param chain Jellyfish chain.
         * @return Number of user-input/output pairs.
         */
        static int turn_count(const fossil_jellyfish_chain_t *chain) {
            return fossil_io_chat_turn_count(chain);
        }

        /**
         * @brief Summarizes the session into a concise text form.
         * 
         * This scans the chat blocks and returns a summary paragraph based on user turns.
         * 
         * @param chain Jellyfish chain to summarize.
         * @param summary Output buffer to store summary.
         * @param size Size of the output buffer.
         * @return 0 on success, -1 if summary couldn't be generated.
         */
        static int summarize_session(const fossil_jellyfish_chain_t *chain, char *summary, size_t size) {
            return fossil_io_chat_summarize_session(chain, summary, size);
        }

        /**
         * @brief Filters the most recent N turns into a temporary sub-chain.
         * 
         * Useful for generating context-limited decisions.
         * 
         * @param chain Original chat chain.
         * @param out_chain Output chain filled with most recent turns.
         * @param turn_count Number of recent user turns to include.
         * @return 0 on success.
         */
        static int filter_recent(const fossil_jellyfish_chain_t *chain, fossil_jellyfish_chain_t *out_chain, int turn_count) {
            return fossil_io_chat_filter_recent(chain, out_chain, turn_count);
        }

        /**
         * @brief Exports the current conversation history to a text file.
         * 
         * @param chain Jellyfish chain to serialize.
         * @param filepath Destination path for output.
         * @return 0 on success, -1 on error.
         */
        static int export_history(const fossil_jellyfish_chain_t *chain, const char *filepath) {
            return fossil_io_chat_export_history(chain, filepath);
        }

        /**
         * @brief Imports a context file and loads it into the chain.
         * 
         * Useful for bootstrapping or restoring previous sessions.
         * 
         * @param chain Destination Jellyfish chain.
         * @param filepath Source path of saved context.
         * @return 0 on success, -1 if parsing fails.
         */
        static int import_context(fossil_jellyfish_chain_t *chain, const char *filepath) {
            return fossil_io_chat_import_context(chain, filepath);
        }
    };

} // namespace ai

} // namespace fossil

#endif

#endif /* fossil_fish_FRAMEWORK_H */
