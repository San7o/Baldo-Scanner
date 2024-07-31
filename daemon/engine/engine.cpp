#include "daemon/engine.hpp"
#include "common/logger.hpp"
#include "daemon/yara.hpp"

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <iostream>
#include <cerrno>
#include <vector>
#include <fstream>
#include <sstream>
#include <sqlite3.h>
#include <iomanip>

using namespace AV;

Engine::Engine(std::string filePath, std::string yaraRulesPath)
{
    this->filePath = filePath;
    this->yaraRulesPath = yaraRulesPath;
}

void Engine::scan(Enums::ScanType scan_type)
{
    if (scan_type == Enums::ScanType::SIGNATURE)
        scanSignature();
    else if (scan_type == Enums::ScanType::RULES)
        scanYaraRules();
    else if (scan_type == Enums::ScanType::ALL)
    {
        scanSignature();
        scanYaraRules();
    }
}

void sha256_file(const std::string& filename, unsigned char* output)
{
    std::ifstream file(filename, std::ios::binary);
    if (!file)
    {
        perror("Error opening file");
    }

    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (!context)
    {
        ERR_print_errors_fp(stderr);
        return;
    }

    if (1 != EVP_DigestInit_ex(context, EVP_sha256(), nullptr))
    {
        ERR_print_errors_fp(stderr);
        return;
    }

    const std::streamsize bufferSize = 4096;
    std::vector<char> buffer(bufferSize);
    while (file.good())
    {
        file.read(buffer.data(), buffer.size());
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0)
        {
            if (1 != EVP_DigestUpdate(context, buffer.data(), bytesRead))
            {
                ERR_print_errors_fp(stderr);
                return;
            }
        }
    }

    if (file.bad())
    {
        ERR_print_errors_fp(stderr);
        return;
    }

    unsigned int lengthOfHash = 0;
    if (1 != EVP_DigestFinal_ex(context, output, &lengthOfHash))
    {
        ERR_print_errors_fp(stderr);
        return;
    }

    EVP_MD_CTX_free(context);
}

void check_sqlite_error(int rc, sqlite3* db)
{
    if (rc != SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        exit(rc);
    }
}

// TODO move to class
void Engine::scanSignature()
{
    MalwareDB db("/etc/antivirus/signatures.db");
    int rc = sqlite3_open("/etc/antivirus/signatures.db", &db.connection);
    check_sqlite_error(rc, db.connection);

    if (db.connection == nullptr)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Database not connected yet");
        return;
    }

    unsigned char md[EVP_MAX_MD_SIZE];
    sha256_file(this->filePath, md);

    std::stringstream ss;
    for (size_t i = 0; i < 32; i++)
    {
         ss << std::hex << std::setw(2) << std::setfill('0') << (int) md[i];
    }
    std::string sha_string(ss.str());
    //std::cout << "The sha256 is: " << sha_string << std::endl;

    // Query the database for the hash
    std::string query = "SELECT sha256_hash FROM signatures WHERE sha256_hash = ?;";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db.connection, query.c_str(), -1, &stmt, nullptr);
    check_sqlite_error(rc, db.connection);

    Logger::Log(Enums::LogLevel::INFO, "Querying database for SHA");
    std::cout << std::flush;

    rc = sqlite3_exec(db.connection, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
    check_sqlite_error(rc, db.connection);

    rc = sqlite3_bind_text(stmt, 1, sha_string.c_str(), -1, SQLITE_TRANSIENT);
    check_sqlite_error(rc, db.connection);

    Logger::Log(Enums::LogLevel::INFO, "Executing query");

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        Logger::Log(Enums::LogLevel::INFO, "Malware detected in file: " + this->filePath);
    }

    if (rc != SQLITE_DONE)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Error executing query");
        sqlite3_finalize(stmt);
        return;
    }

    rc = sqlite3_exec(db.connection, "END TRANSACTION;", nullptr, nullptr, nullptr);
    check_sqlite_error(rc, db.connection);

    Logger::Log(Enums::LogLevel::INFO, "Query completed");
    sqlite3_finalize(stmt);
}

void Engine::stop()
{
    // TODO
}

void Engine::scanYaraRules()
{
    YR_RULES* rules;
    Yara::LoadRules(this->yaraRulesPath, &rules);
    Yara::Scan(rules, this->filePath);
}
