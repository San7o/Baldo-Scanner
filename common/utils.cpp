// SPDX-License-Identifier: MIT
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#include <baldo/common/utils.hpp>
#include <baldo/common/logger.hpp>

using namespace baldo;

void baldo::check_sqlite_error(int rc, sqlite3* db)
{
  if (rc != SQLITE_OK)
  {
    Logger::Log(Enums::LogLevel::ERROR, "SQLite error: " +
                std::string(sqlite3_errmsg(db)));
    sqlite3_close(db);
    exit(rc);
  }

  return;
}
