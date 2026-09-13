# Makefile para Evergram SDK C

CC = gcc
AR = ar
CFLAGS = -Wall -Wextra  -std=gnu11 -fPIC -I./include -I./src/proto
LDFLAGS = -shared

# Bibliotecas externas
# Para produção, descomente todas as dependências:
# LIBS = -lsodium -lwebsockets -lprotobuf-c -lcurl

# Modo produção (com todas as dependências)
LIBS = -lsodium -lwebsockets -lprotobuf-c -lssl -lcrypto

# Debug flags
ifdef DEBUG
CFLAGS += -g -O0 -DDEBUG
endif

# Release flags
ifdef RELEASE
CFLAGS += -O3 -DNDEBUG
endif 

# Diretórios
SRC_DIR = src
INC_DIR = include
OBJ_DIR = obj
LIB_DIR = lib
BIN_DIR = bin

# Arquivos fonte
SRCS = $(wildcard $(SRC_DIR)/*.c) $(wildcard $(SRC_DIR)/proto/*.pb-c.c)
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Biblioteca estática
LIB_STATIC = $(LIB_DIR)/libevergram.a

# Biblioteca compartilhada
LIB_SHARED = $(LIB_DIR)/libevergram.so

# Exemplos
EXAMPLES = $(BIN_DIR)/echo-bot

# Alvo padrão
all: dirs $(LIB_STATIC) $(LIB_SHARED) examples

# Criar diretórios
dirs:
	@mkdir -p $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)

# Compilar objetos
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Criar biblioteca estática
$(LIB_STATIC): $(OBJS)
	$(AR) rcs $@ $^
	@echo "Biblioteca estática criada: $@"

# Criar biblioteca compartilhada
$(LIB_SHARED): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)
	@echo "Biblioteca compartilhada criada: $@"

# Compilar exemplos
examples: $(EXAMPLES)

$(BIN_DIR)/echo-bot: examples/echo-bot.c $(LIB_STATIC)
	$(CC) $(CFLAGS) -o $@ $< -L$(LIB_DIR) -levergram $(LIBS)
	@echo "Exemplo compilado: $@"

# Instalar biblioteca (requer sudo)
install: $(LIB_STATIC) $(LIB_SHARED)
	cp $(INC_DIR)/evergram.h /usr/local/include/
	cp $(LIB_STATIC) /usr/local/lib/
	cp $(LIB_SHARED) /usr/local/lib/
	ldconfig
	@echo "Evergram SDK instalado em /usr/local"

# Desinstalar
uninstall:
	rm -f /usr/local/include/evergram.h
	rm -f /usr/local/lib/libevergram.a
	rm -f /usr/local/lib/libevergram.so
	ldconfig
	@echo "Evergram SDK desinstalado"

# Limpar
clean:
	rm -rf $(OBJ_DIR) $(LIB_DIR) $(BIN_DIR)
	@echo "Build limpo"

# Rebuild completo
rebuild: clean all

# Testar compilação do exemplo (sem executar)
test-build: $(BIN_DIR)/echo-bot
	@echo "Compilação OK!"
	@echo "Para executar: cd $(BIN_DIR) && ./echo-bot --help"

# Debug build
debug: CFLAGS += -g -O0 -DDEBUG
debug: clean all

# Release build
release: CFLAGS += -O3 -DNDEBUG
release: clean all

# Mostrar ajuda
help:
	@echo "Evergram SDK C - Makefile Targets:"
	@echo "  all          - Build tudo (default)"
	@echo "  dirs         - Cria diretórios necessários"
	@echo "  examples     - Compila exemplos"
	@echo "  install      - Instala no sistema (sudo necessário)"
	@echo "  uninstall    - Remove do sistema"
	@echo "  clean        - Remove arquivos de build"
	@echo "  rebuild      - Clean + all"
	@echo "  test-build   - Testa compilação"
	@echo "  debug        - Build com debug symbols"
	@echo "  release      - Build otimizado"
	@echo "  help         - Mostra esta ajuda"
	@echo ""
	@echo "Dependências (linkadas):"
	@echo "  libsodium     - Criptografia (Ed25519, X25519, secretbox)"
	@echo "  libwebsockets - Transporte WebSocket"
	@echo "  protobuf-c    - Serialização protobuf"
	@echo "  openssl       - SHA-256/SHA-512/RIPEMD-160 (chaves/endereços XRPL)"
	@echo ""
	@echo "Nota: sem Node.js/npm. As chaves e assinaturas XRPL são"
	@echo "reimplementadas em C (src/crypto_xrpl.c)."

.PHONY: all dirs examples install uninstall clean rebuild test-build debug release help
