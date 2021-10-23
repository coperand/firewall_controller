CC = g++
CLEAN = rm -f

PROG_NAME = graduation
BIN_DIR = binary
SOURCES = $(wildcard *.cpp)
LIBS = -lip4tc -lnetsnmp -lnetsnmpagent


all:
	mkdir -p $(BIN_DIR)
	$(CC) $(SOURCES) $(LIBS) -o $(BIN_DIR)/$(PROG_NAME)

cl: clean
clean:
	$(CLEAN) $(BIN_DIR)/$(PROG_NAME)