#pragma once

#include <chrono>
#include <ctime>
#include <iostream>
#include <sstream>
#include <string>
#include <windows.h> // Windows API for console colors

namespace logger {
// Windows 控制台颜色常量 (前景)
// 这些是标准定义的颜色值，用于 SetConsoleTextAttribute
enum class LogColor {
    GREEN = FOREGROUND_GREEN | FOREGROUND_INTENSITY, // 绿色
    YELLOW = FOREGROUND_RED | FOREGROUND_GREEN |
             FOREGROUND_INTENSITY,               // 亮黄色 (亮红+亮绿)
    RED = FOREGROUND_RED | FOREGROUND_INTENSITY, // 亮红色
    BLUE = FOREGROUND_BLUE | FOREGROUND_INTENSITY, // 亮蓝色
    WHITE = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE // 默认白色
};

/**
 * @brief 自定义 ostream 缓冲区，用于捕获日志内容并在析构时输出
 */
class LogStreamBuffer : public std::stringbuf {
    public:
    LogStreamBuffer(const std::string &type, LogColor color)
        : logType(type), logColor(color) {
    }

    // 析构函数：在流结束（例如 std::endl 或对象销毁）时输出日志
    ~LogStreamBuffer() {
        pubsync();
    }

    protected:
    // 同步（实际输出）函数，当调用 std::endl 或 flush 时触发
    virtual int sync() override {
        // 使用 std::stringbuf::pbase() 和 std::stringbuf::pptr() 来判断是否有数据
        // 而不是依赖 str().empty()，因为 str() 对空字符的处理可能有问题。
        // pptr() 指向下一个要插入的位置，pbase() 指向缓冲区的起始位置。
        // 如果它们不相等，说明缓冲区中有内容。
        if (pbase() != pptr()) { // 检查缓冲区是否包含任何内容

            std::string log_message = str(); // 提取内容

            // 1. 获取并格式化当前时间
            auto now = std::chrono::system_clock::now();
            auto now_t = std::chrono::system_clock::to_time_t(now);
            struct tm tstruct;
            // 使用 localtime_s (Windows安全版本)
            if (localtime_s(&tstruct, &now_t) == 0) {
                char buf[80];
                // 格式化时间: YYYY-MM-DD HH:MM:SS
                std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tstruct);

                // 2. 设置控制台颜色
                HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
                WORD originalAttributes = 0;
                CONSOLE_SCREEN_BUFFER_INFO consoleInfo;

                // 尝试获取原始属性以便恢复
                if (GetConsoleScreenBufferInfo(hConsole, &consoleInfo)) {
                    originalAttributes = consoleInfo.wAttributes;
                }

                SetConsoleTextAttribute(hConsole, static_cast<WORD>(logColor));

                // 3. 输出完整的日志信息
                // 格式: date [Type] message
                std::cout << buf << " [" << logType << "] " << log_message;

                // 4. 恢复控制台颜色
                SetConsoleTextAttribute(hConsole, originalAttributes);

                // 5. 清空缓冲区
                str(""); // 清空缓冲区内容
                setp(pbase(), epptr()); // 重置缓冲区指针
                return 0; // 成功
            }
        }
        
        // 即使没有内容，如果缓冲区指针不一致，也尝试重置。
        if (pbase() != pptr()) {
            str("");
            setp(pbase(), epptr());
        }

        // 如果缓冲区为空，返回成功，否则返回 -1 表示失败
        return 0; 
    }

    private:
    std::string logType;
    LogColor logColor;
};

/**
 * @brief 日志流类，继承自 std::ostream
 */
class LogStream : public std::ostream {
    public:
    LogStream(const std::string &type, LogColor color)
        : std::ostream(new LogStreamBuffer(type, color)) {
    }

    // 析构函数：清理自定义的 streambuf
    ~LogStream() {
        delete rdbuf();
    }
};

// 全局日志流对象
extern LogStream info;
extern LogStream warn;
extern LogStream error;
extern LogStream debug;
} // namespace logger