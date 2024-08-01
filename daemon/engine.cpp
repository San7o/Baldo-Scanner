#include "daemon/engine.hpp"
#include "common/logger.hpp"
#include "daemon/yara.hpp"
#include "daemon/daemon.hpp"

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

Engine::Engine(std::string filePath, ScanReport* report)
{
    this->filePath = filePath;
    this->report = report;
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
    Logger::Log(Enums::LogLevel::DEBUG, "SHA256: " + sha_string);

    // Query the database for the hash
    std::string query = "SELECT sha256_hash FROM signatures WHERE sha256_hash = ?;";

    sqlite3_stmt* stmt;
    rc = sqlite3_prepare_v2(db.connection, query.c_str(), -1, &stmt, nullptr);
    check_sqlite_error(rc, db.connection);

    Logger::Log(Enums::LogLevel::DEBUG, "Querying database for SHA");
    std::cout << std::flush;

    rc = sqlite3_exec(db.connection, "BEGIN TRANSACTION;", nullptr, nullptr, nullptr);
    check_sqlite_error(rc, db.connection);

    rc = sqlite3_bind_text(stmt, 1, sha_string.c_str(), -1, SQLITE_TRANSIENT);
    check_sqlite_error(rc, db.connection);

    Logger::Log(Enums::LogLevel::DEBUG, "Executing query");

    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW)
    {
        Logger::Log(Enums::LogLevel::INFO, "Malware detected in file: " + this->filePath);

        // Produce Report
        const unsigned char* sha256_hash = sqlite3_column_text(stmt, 1);
        const unsigned char* file_name   = sqlite3_column_text(stmt, 5);
        const unsigned char* file_type_guess = sqlite3_column_text(stmt, 6);
        const unsigned char* mime_type   = sqlite3_column_text(stmt, 7);
        const unsigned char* signature   = sqlite3_column_text(stmt, 8);

        this->report->append("Malware detected in file: " + this->filePath + "\n");
        this->report->append("SHA256: ");
        this->report->append(sha256_hash);
        this->report->append("\nFile name: ");
        this->report->append(file_name);
        this->report->append("\nFile type guess: ");
        this->report->append(file_type_guess);
        this->report->append("\nMime type: ");
        this->report->append(mime_type);
        this->report->append("\nSignature: ");
        this->report->append(signature);
        this->report->append("\n");
    }

    if (rc != SQLITE_DONE)
    {
        Logger::Log(Enums::LogLevel::ERROR, "Error executing query");
        sqlite3_finalize(stmt);
        return;
    }

    rc = sqlite3_exec(db.connection, "END TRANSACTION;", nullptr, nullptr, nullptr);
    check_sqlite_error(rc, db.connection);

    Logger::Log(Enums::LogLevel::DEBUG, "Query completed");
    sqlite3_finalize(stmt);
}

void Engine::scanYaraRules()
{
    YR_RULES* rules;
    Yara::LoadRules(RULES_PATH, &rules);
    Yara::Scan(rules, this->filePath, this->report);
}

void ScanReport::append(std::string message)
{
    this->report_mutex.lock();
    this->report += message;
    this->report_mutex.unlock();
}

void ScanReport::append(const unsigned char* c)
{
    this->report_mutex.lock();
    this->report += std::string(reinterpret_cast<const char*>(c));
    this->report_mutex.unlock();
}
