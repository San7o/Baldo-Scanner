#include "daemon/yara.hpp"
#include "daemon/daemon.hpp"
#include "common/logger.hpp"

#include <filesystem>
#include <string>
#include <fstream>
#include <vector>
#include <iostream>

#include <yara.h>

using namespace AV;

void Yara::callback_compilation(int error_level, const char* file_name, int line_number,
                               const YR_RULE* rule, const char* message, void* user_data)
{
    switch(error_level)
    {
        case YARA_ERROR_LEVEL_ERROR:
            Logger::Log(Enums::LogLevel::ERROR, "Error: " + std::string(message) + " in " +
                    std::string(file_name) + " at line " + std::to_string(line_number));
            break;
        case YARA_ERROR_LEVEL_WARNING:
            Logger::Log(Enums::LogLevel::WARN, "Warning: " + std::string(message) + " in " +
                    std::string(file_name) + " at line " + std::to_string(line_number));
            break;
        default:
            break;
    }
}

void Yara::CompileRules(std::string yaraRulesPath)
{
    YR_COMPILER* compiler;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Failed to create compiler");
        return;
    }

    yr_compiler_set_callback(compiler, callback_compilation, NULL);

    std::vector<FILE*> files;
    for (auto &rule : std::filesystem::directory_iterator(yaraRulesPath))
    {
        if (rule.path().extension() != ".yar")
        {
            continue;
        }

        // This file causes problems
        if (rule.path().filename() == "yes.yar")
        {
            continue;
        }

        FILE* file = fopen(rule.path().c_str(), "r");
        if (file == NULL)
        {
            Logger::Log(Enums::LogLevel::ERROR, "Failed to open rule: " + rule.path().string());
        }
        files.push_back(file);
        if (yr_compiler_add_file(compiler, file, NULL, rule.path().c_str()) != 0)
        {
            Logger::Log(Enums::LogLevel::ERROR, "Failed to add rule: " + rule.path().string());
        }
    }
   
    // Save rules
    YR_RULES *rules;
    if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Failed to get rules");
    }

    if (yr_rules_save(rules, RULES_PATH) != 0)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Failed to save compiled rules");
    }

    yr_compiler_destroy(compiler);
    for (auto &file : files)
    {
        fclose(file);
    }
}

void Yara::LoadRules(std::string yaraRulesPath, YR_RULES** rules)
{
    Logger::Log(Enums::LogLevel::DEBUG, "Loading rules");
    if (yr_rules_load("/etc/antivirus/compiled_rules.yar", rules) != ERROR_SUCCESS)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Failed to load rules");
    }
}

/**
 * This funcion gets called with different messages and message_data
 * based on the scan context. The message is one of the following:
 *
 * - CALLBACK_MSG_RULE_MATCHING
 * - CALLBACK_MSG_RULE_NOT_MATCHING
 * - CALLBACK_MSG_SCAN_FINISHED
 * - CALLBACK_MSG_IMPORT_MODULE
 * - CALLBACK_MSG_MODULE_IMPORTED
 * - CALLBACK_MSG_TOO_MANY_MATCHES
 * - CALLBACK_MSG_CONSOLE_LOG
 * 
 * Depending on the message, the message_data is different.
*/
int Yara::callback_scan(YR_SCAN_CONTEXT* context, int message,
                  void* message_data, void* user_data)
{
    if (message == CALLBACK_MSG_RULE_MATCHING)
    {
        YR_RULE* rule = (YR_RULE*) message_data;
        Logger::Log(Enums::LogLevel::INFO, "Matched rule: " + std::string(rule->identifier));

        // Generate Report
        YaraUserData* data = (YaraUserData*) user_data;
        data->report->append("Matched rule: " +
                             std::string(rule->identifier) +
                             " in file: " + data->path + "\n");
    }
    else if (message == CALLBACK_MSG_SCAN_FINISHED)
    {
        Logger::Log(Enums::LogLevel::DEBUG, "Rules Scan finished");
    }

    return CALLBACK_CONTINUE;
}

void Yara::Scan(YR_RULES* rules, std::string filePath, ScanReport* report)
{
    YaraUserData* data = new YaraUserData();
    data->path = filePath;
    data->report = report;

    int ret = yr_rules_scan_file(rules, filePath.c_str(), 0, callback_scan, (void*) data, 10);
    if (ret != ERROR_SUCCESS)
    {
        switch (ret)
        {
            case ERROR_INSUFFICIENT_MEMORY:
                Logger::Log(Enums::LogLevel::ERROR, "Insufficient memory");
                break;
            case ERROR_COULD_NOT_MAP_FILE:
                Logger::Log(Enums::LogLevel::ERROR, "Could not map file");
                break;
            case ERROR_TOO_MANY_SCAN_THREADS:
                Logger::Log(Enums::LogLevel::ERROR, "Too many scan threads");
                break;
            case ERROR_SCAN_TIMEOUT:
                Logger::Log(Enums::LogLevel::ERROR, "Scan timeout");
                break;
            case ERROR_CALLBACK_ERROR:
                Logger::Log(Enums::LogLevel::ERROR, "Callback error");
                break;
            case ERROR_TOO_MANY_MATCHES:
                Logger::Log(Enums::LogLevel::ERROR, "Error scanning file");
                break;
            default:
                Logger::Log(Enums::LogLevel::ERROR, "Error scanning file");
                break;
        }
    }
    delete data;
}
