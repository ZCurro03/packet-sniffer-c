CC = gcc -g
CFLAGS = -Wall -Wextra

EXE = sniffer
LIBS = -lpcap
HEADER = include/packet_handler.h include/signal_handler.h include/device_manager.h include/ui.h
OBJ = obj/main.o obj/packet_handler.o obj/signal_handler.o obj/device_manager.o obj/ui.o

all: compile run

compile: $(EXE)
	@echo "[MAKEFILE] Packet sniffer compiled successfully and ready to run."

run: $(EXE)
	@echo "[MAKEFILE] Running packet sniffer..."
	./$(EXE)

run_v: $(EXE)
	@echo "[MAKEFILE] Running packet sniffer with Valgrind..."
	valgrind --leak-check=full --track-origins=yes --show-leak-kinds=all ./$(EXE)

full_clean:
	@echo "[MAKEFILE] Cleaning all binary files and executables..."
	@rm -f $(EXE) obj/*.o

clean:
	@echo "[MAKEFILE] Cleaning all binary files..."
	@rm -f obj/*.o

$(EXE): $(OBJ)
	@$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

obj/main.o: src/main.c $(HEADER)
	@$(CC) $(CFLAGS) -c $< -o $@

obj/packet_handler.o: src/packet_handler.c include/packet_handler.h
	@$(CC) $(CFLAGS) -c $< -o $@

obj/signal_handler.o: src/signal_handler.c include/signal_handler.h
	@$(CC) $(CFLAGS) -c $< -o $@

obj/device_manager.o: src/device_manager.c include/device_manager.h
	@$(CC) $(CFLAGS) -c $< -o $@

obj/ui.o: src/ui.c include/ui.h
	@$(CC) $(CFLAGS) -c $< -o $@
