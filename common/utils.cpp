#include "common/utils.hpp"
#include "common/logger.hpp"

using namespace AV;

void check_sqlite_error(int rc, sqlite3* db)
{
    if (rc != SQLITE_OK) {
        Logger::Log(Enums::LogLevel::ERROR, "SQLite error: " +
                        std::string(sqlite3_errmsg(db)));
        sqlite3_close(db);
        exit(rc);
    }
}
