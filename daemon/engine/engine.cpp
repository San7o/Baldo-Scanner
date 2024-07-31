#include "daemon/engine.hpp"
#include "common/logger.hpp"
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

Engine::Engine(std::string filePath, std::string yaraRulesPath, MalwareDB* db)
{
    this->filePath = filePath;
    this->yaraRulesPath = yaraRulesPath;
    this->db = db;
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

void sha256_file(const std::string& filename, unsigned char* output) {

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
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
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            if (1 != EVP_DigestUpdate(context, buffer.data(), bytesRead))
            {
                ERR_print_errors_fp(stderr);
                return;
            }
        }
    }

    if (file.bad()) {
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

void check_sqlite_error(int rc, sqlite3* db) {
    if (rc != SQLITE_OK) {
        std::cerr << "SQLite error: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        exit(rc);
    }
}

void Engine::scanSignature()
{
    unsigned char md[EVP_MAX_MD_SIZE];
    sha256_file(this->filePath, md);

    std::stringstream ss;
    for (size_t i = 0; i < 32; i++)
    {
         ss << std::hex << (int) md[i];
    }
    std::string sha_string(ss.str());
    std::cout << "The sha is: " << sha_string << std::endl;

    // Query the database for the hash
    std::string query = "SELECT column2 FROM signatures WHERE column2 = \"" + sha_string + "\";";
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(this->db->connection, query.c_str(), -1, &stmt, 0);
    check_sqlite_error(rc, this->db->connection);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char* sha = sqlite3_column_text(stmt, 0);
        Logger::Log(Enums::LogLevel::INFO, "Found!");
        delete sha;
    }
    sqlite3_finalize(stmt);
}

void Engine::scanYaraRules()
{
    
}

void Engine::stop()
{
    
}
