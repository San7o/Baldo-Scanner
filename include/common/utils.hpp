#pragma once

#include <sqlite3.h>
#include "common/logger.hpp"

void check_sqlite_error(int rc, sqlite3* db);
