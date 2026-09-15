###########################
#      FLAGS & MACROS     #
###########################

# === Tools and flags ===
CC = gcc
CFLAGS = -Wall -Wextra -g -Iinclude
DEPFLAGS = -MMD -MP
VALGRIND = valgrind --leak-check=full --track-origins=yes --show-leak-kinds=all

# === Executable and libraries ===
LIBS = -lpcap
EXE = sniffer

# === Directories ===
SRC_DIR = src
OBJ_DIR = obj

# === Source files ===
SRCS = $(wildcard $(SRC_DIR)/*.c)

# === Obj files ===
OBJS = $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))

# === Dependencies ===
DEPS = $(OBJS:.o=.d)

###########################
#         COMMANDS        #
###########################

all: compile run

compile: $(EXE)
	@echo "[MAKEFILE] Packet sniffer compiled successfully and ready to run."

setcap: $(EXE)
	@echo "[MAKEFILE] Setting network capabilities (sudo required)..."
	@sudo setcap cap_net_raw,cap_net_admin=eip $(EXE)
	@echo "[MAKEFILE] Capabilities set successfully. You can now run './$(EXE)' without sudo."

run: $(EXE)
	@echo "[MAKEFILE] Running packet sniffer..."
	./$(EXE)

run_v: $(EXE)
	@echo "[MAKEFILE] Running packet sniffer with Valgrind..."
	$(VALGRIND) ./$(EXE)

full_clean:
	@echo "[MAKEFILE] Cleaning all binary files and executables..."
	@rm -rf $(OBJ_DIR) $(EXE)

clean:
	@echo "[MAKEFILE] Cleaning all binary files..."
	@rm -rf $(OBJ_DIR)

###########################
#       COMPILATION       #
###########################

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	@$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

$(EXE): $(OBJS)
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

###########################
#   INCLUDE DEPENDENCIES  #
###########################

-include $(DEPS)
