#include "logger.h"

namespace logger {
LogStream info("INFO", LogColor::GREEN);
LogStream warn("WARN", LogColor::YELLOW);
LogStream error("ERROR", LogColor::RED);
} // namespace logger