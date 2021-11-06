CC = g++
CLEAN = rm -f
DEB_BUILD = dpkg-deb --build

PROG_NAME = fcontroller
BIN_DIR = binary
DEB_DIR = deb
FINAL_PATH = usr/bin
SOURCES = $(wildcard *.cpp)
FLAGS = -Wall -Weffc++
LIBS = -lip4tc -lnetsnmp -lnetsnmpagent -lsqlite3


all:
	mkdir -p $(BIN_DIR)
	$(CC) $(SOURCES) $(FLAGS) $(LIBS) -o $(BIN_DIR)/$(PROG_NAME)

deb: all
	cp $(BIN_DIR)/$(PROG_NAME) $(DEB_DIR)/$(PROG_NAME)/$(FINAL_PATH)
	$(DEB_BUILD) $(DEB_DIR)/$(PROG_NAME) $(BIN_DIR)

cl: clean
clean:
	$(CLEAN) $(BIN_DIR)/*
	$(CLEAN) $(DEB_DIR)/$(PROG_NAME)/$(FINAL_PATH)/$(PROG_NAME)