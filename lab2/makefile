CXX = g++
CXXFLAGS = -Wall -std=c++17 -I.
LDFLAGS = -lWs2_32

# Debug 模式的编译选项
DEBUG_CXXFLAGS = $(CXXFLAGS) -g -DDEBUG

SRCDIR = .
LOG_SRC_PATH = ../logger/logger.cpp

TARGETS = server client tunnel

# 定义对象文件目录 (可选，用于保持工作区整洁)
OBJDIR = obj
# 创建一个对象文件列表 (通过替换 .cpp 为 .o 并调整路径)
# 注意：logger.cpp 的对象文件路径也需要处理
SERVER_OBJS = $(OBJDIR)/server.o $(OBJDIR)/GBNmanager.o $(OBJDIR)/logger.o
CLIENT_OBJS = $(OBJDIR)/client.o $(OBJDIR)/GBNmanager.o $(OBJDIR)/logger.o
TUNNEL_OBJS = $(OBJDIR)/tunnel.o $(OBJDIR)/logger.o

# 默认目标：编译所有可执行文件
all: $(TARGETS)

# 确保 obj 目录存在
$(OBJDIR):
	mkdir -p $(OBJDIR)

# ----------------- 编译目标 -----------------

server: $(OBJDIR) $(SERVER_OBJS)
	$(CXX) $(SERVER_OBJS) -o $@ $(LDFLAGS)

client: $(OBJDIR) $(CLIENT_OBJS)
	$(CXX) $(CLIENT_OBJS) -o $@ $(LDFLAGS)

tunnel: $(OBJDIR) $(TUNNEL_OBJS)
	$(CXX) $(TUNNEL_OBJS) -o $@ $(LDFLAGS)

# ----------------- 编译规则 -----------------

# 通用规则：将当前目录的 .cpp 文件编译为 obj/ 目录下的 .o 文件
$(OBJDIR)/%.o: $(SRCDIR)/%.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# 特殊规则：编译 logger.cpp (因为它的源文件在不同的路径)
$(OBJDIR)/logger.o: $(LOG_SRC_PATH)
	$(CXX) $(CXXFLAGS) -c $< -o $@

# ----------------- Debug 目标 -----------------
debug: CXXFLAGS = $(DEBUG_CXXFLAGS)
debug: all

# ----------------- 清理目标 -----------------
clean:
	rm -f $(OBJDIR)/*.o $(TARGETS)

.PHONY: all clean debug