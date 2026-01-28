// SPDX-License-Identifier: MIT
// Author:  Giovanni Santini
// Mail:    giovanni.santini@proton.me
// Github:  @San7o

#pragma once

#include <sqlite3.h>

#include <baldo/common/logger.hpp>

namespace baldo
{

void check_sqlite_error(int rc, sqlite3* db);

}
