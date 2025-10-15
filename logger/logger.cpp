#include "logger.h"

namespace logger {
LogStream info("INFO", LogColor::GREEN);
LogStream warn("WARN", LogColor::YELLOW);
LogStream error("ERROR", LogColor::RED);
LogStream debug("DEBUG", LogColor::BLUE);
} // namespace logger