CC = g++
CLEAN = rm -f

PROG_NAME = graduation
BIN_DIR = binary
SOURCES = $(wildcard *.cpp)
FLAGS = -Wall -Weffc++
LIBS = -lip4tc -lnetsnmp -lnetsnmpagent -lsqlite3


all:
	mkdir -p $(BIN_DIR)
	$(CC) $(SOURCES) $(FLAGS) $(LIBS) -o $(BIN_DIR)/$(PROG_NAME)

cl: clean
clean:
	$(CLEAN) $(BIN_DIR)/$(PROG_NAME)