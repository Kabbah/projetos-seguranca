# Opções do compilador
CC = g++
CFLAGS = -Wall -std=c++11
LDFLAGS = 

# Nome do executável
BIN = analisador-freq

# Diretórios
SRC_DIR = ./src
BUILD_DIR = ./build

# Código-fonte (emendar outros wildcards caso tenha mais diretórios)
CPP = $(wildcard $(SRC_DIR)/*.cpp)
HEADERS = $(wildcard $(SRC_DIR)/*.h)

# Objetos
OBJ = $(subst $(SRC_DIR),$(BUILD_DIR),$(CPP:%.cpp=%.cpp.o))

# Makefile targets

.PHONY = default all clean

default: $(BIN)
all: default

$(BUILD_DIR)/%.cpp.o: $(SRC_DIR)/%.cpp $(HEADERS)
	@echo "CC      $<"
	@mkdir -p $(@D)
	@$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJ)
	@echo "LD      $<"
	@$(CC) $(LDFLAGS) $(OBJ) -o $@

clean:
	-rm -f $(BIN)
	-rm -f $(BUILD_DIR)/*.cpp.o
