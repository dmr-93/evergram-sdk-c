#include <evergram.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

// Variável global para controle de loop
static int running = 1;

// Handler para SIGINT (Ctrl+C)
void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

// Função auxiliar para imprimir buffer em hex
void print_hex_dump(const char *label, const unsigned char *buf, size_t len) {
    printf("[DEBUG %s] Dump Hex (%zu bytes): ", label, len);
    for (size_t i = 0; i < len && i < 64; i++) {
        printf("%02x", buf[i]);
        if ((i + 1) % 4 == 0) printf(" ");
        if ((i + 1) % 16 == 0) printf("\n                    ");
    }
    if (len > 64) printf("\n                    ... (%zu bytes total)", len);
    printf("\n");
    
    // Tenta imprimir como string se for texto imprimível
    if (len > 0 && len < 512) {
        int is_printable = 1;
        for (size_t i = 0; i < len; i++) {
            if (buf[i] < 32 || buf[i] > 126) {
                is_printable = 0;
                break;
            }
        }
        if (is_printable) {
            printf("[DEBUG %s] String: %.*s\n", label, (int)len, (char*)buf);
        }
    }
}

// Callback para mensagens recebidas
void on_message(evergram_t* eg, const evergram_message_t* msg) {
    printf("\n[=== MENSAGEM RECEBIDA ===]\n");
    if (!msg) {
        printf("[Mensagem] MSG NULA!\n");
        return;
    }
    
    printf("[Mensagem] Chat: %s\n", msg->chat_id ? msg->chat_id : "N/A");
    printf("[Mensagem] De: %s\n", msg->sender ? msg->sender : "N/A");
    printf("[Mensagem] Texto: %s\n", msg->text ? msg->text : "N/A");
    
    if (msg->reply_to_msg_id) {
        printf("[Mensagem] Resposta para: %s\n", msg->reply_to_msg_id);
    }
    
    evergram_wallet_t* wallet = (evergram_wallet_t*)evergram_get_user_data(eg);
    if (wallet && msg->sender && strcmp(msg->sender, wallet->address) == 0) {
        printf("[Mensagem] Ignorando mensagem do próprio bot\n");
        return;
    }
    
    // Responder com eco
    printf("[Mensagem] Respondendo com eco...\n");
    int ret = evergram_reply(eg, msg, "Echo: %s", msg->text);
    if (ret != EVERGRAM_SUCCESS) {
        fprintf(stderr, "[Mensagem] Erro ao responder: %s\n", evergram_strerror(ret));
    } else {
        printf("[Mensagem] Eco enviado com sucesso!\n");
    }
    printf("[==========================]\n\n");
}

// Callback para reações
void on_reaction(evergram_t* eg, const evergram_reaction_t* reaction) {
    (void)eg;  // Não usado no stub
    printf("\n[=== REAÇÃO RECEBIDA ===]\n");
    if (!reaction) {
        printf("[Reação] REAÇÃO NULA!\n");
        return;
    }
    
    printf("[Reação] Chat: %s, Msg: %s, Emoji: %s, Removida: %s\n",
           reaction->chat_id ? reaction->chat_id : "N/A",
           reaction->msg_id ? reaction->msg_id : "N/A",
           reaction->emoji ? reaction->emoji : "N/A",
           reaction->removed ? "sim" : "não");
    printf("[==========================]\n\n");
}

// Callback para eventos de digitação
void on_typing(evergram_t* eg, const evergram_typing_event_t* event) {
    (void)eg;  // Não usado no stub
    printf("\n[=== EVENTO DE DIGITAÇÃO ===]\n");
    if (!event) {
        printf("[Digitação] EVENTO NULO!\n");
        return;
    }
    
    printf("[Digitação] Chat: %s, Usuário: %s, %s digitando\n",
           event->chat_id ? event->chat_id : "N/A",
           event->sender ? event->sender : "N/A",
           event->is_typing ? "está" : "parou de");
    printf("[==========================]\n\n");
}

// Callback para erros
void on_error(evergram_t* eg, evergram_error_t error, const char* message) {
    (void)eg;  // Não usado no stub
    fprintf(stderr, "\n[=== ERRO ===]\n");
    fprintf(stderr, "[ERRO] Código %d (%s): %s\n", error, evergram_strerror(error), 
            message ? message : "sem detalhes");
    fprintf(stderr, "[==========================]\n\n");
}

// Callback para conexão estabelecida
void on_connected(evergram_t* eg) {
    printf("\n[=== CONEXÃO ESTABELECIDA ===]\n");
    evergram_wallet_t* wallet = (evergram_wallet_t*)evergram_get_user_data(eg);
    if (wallet) {
        printf("[CONECTADO] Bot online como %s\n", wallet->address);
        printf("[CONECTADO] Device ID: %s\n", ((evergram_device_t*)((char*)wallet - sizeof(evergram_wallet_t)))->device_id);
    } else {
        printf("[CONECTADO] Bot online e pronto para receber mensagens!\n");
    }
    printf("[==========================]\n\n");
}

// Callback para desconexão
void on_disconnected(evergram_t* eg) {
    (void)eg;  // Não usado no stub
    printf("\n[=== DESCONECTADO ===]\n");
    printf("[DESCONECTADO] Bot offline.\n");
    printf("[==========================]\n\n");
}

// Função para carregar identidade existente ou criar nova
int load_or_create_identity(evergram_wallet_t* wallet, evergram_device_t* device,
                            const char* identity_file) {
    FILE* f = fopen(identity_file, "r");
    if (f) {
        // Carregar identidade existente
        char line[256];
        
        // Inicializar estrutura
        memset(wallet, 0, sizeof(*wallet));
        memset(device, 0, sizeof(*device));
        
        while (fgets(line, sizeof(line), f)) {
            // Remover newline
            line[strcspn(line, "\r\n")] = 0;
            
            if (strncmp(line, "seed=", 5) == 0) {
                strncpy(wallet->seed, line + 5, sizeof(wallet->seed) - 1);
            } else if (strncmp(line, "address=", 8) == 0) {
                strncpy(wallet->address, line + 8, sizeof(wallet->address) - 1);
            } else if (strncmp(line, "pubkey=", 7) == 0) {
                strncpy(wallet->public_key_hex, line + 7, sizeof(wallet->public_key_hex) - 1);
            } else if (strncmp(line, "privkey=", 8) == 0) {
                // Pode estar vazio ou ter a private key completa
                const char* value = line + 8;
                if (strlen(value) > 0) {
                    strncpy(wallet->private_key_hex, value, sizeof(wallet->private_key_hex) - 1);
                }
            } else if (strncmp(line, "device_pub=", 11) == 0) {
                strncpy(device->pub_hex, line + 11, sizeof(device->pub_hex) - 1);
            } else if (strncmp(line, "device_priv=", 12) == 0) {
                strncpy(device->priv_hex, line + 12, sizeof(device->priv_hex) - 1);
            } else if (strncmp(line, "device_id=", 10) == 0) {
                strncpy(device->device_id, line + 10, sizeof(device->device_id) - 1);
            }
        }
        
        fclose(f);
        
        // Se private_key_hex estiver vazia, usar a seed como private_key
        // A seed tem 64 caracteres hex (32 bytes)
        if (strlen(wallet->private_key_hex) == 0 && strlen(wallet->seed) > 0) {
            printf("[Handshake] Usando seed como chave privada (formato legacy)\n");
            strncpy(wallet->private_key_hex, wallet->seed, sizeof(wallet->private_key_hex) - 1);
            wallet->private_key_hex[sizeof(wallet->private_key_hex) - 1] = '\0';
            printf("[Handshake] Private key hex definida como: %s (len=%zu)\n", wallet->private_key_hex, strlen(wallet->private_key_hex));
        }
        
        printf("[Handshake] Wallet address: %s\n", wallet->address);
        printf("[Handshake] Device ID: %s\n", device->device_id);
        printf("[Handshake] Private key hex length: %zu\n", strlen(wallet->private_key_hex));
        
        printf("Identidade carregada de %s\n", identity_file);
        return 1;
    }
    
    // Criar nova identidade
    printf("Gerando nova identidade...\n");
    
    if (evergram_generate_wallet(wallet) != EVERGRAM_SUCCESS) {
        fprintf(stderr, "Erro ao gerar carteira\n");
        return -1;
    }
    
    if (evergram_generate_device(device) != EVERGRAM_SUCCESS) {
        fprintf(stderr, "Erro ao gerar dispositivo\n");
        return -1;
    }
    
    // Derivar device_id corretamente
    if (evergram_derive_device_id(device->pub_hex, device->device_id) != EVERGRAM_SUCCESS) {
        fprintf(stderr, "Erro ao derivar device_id\n");
        return -1;
    }
    
    // Salvar identidade
    f = fopen(identity_file, "w");
    if (f) {
        fprintf(f, "seed=%s\n", wallet->seed);
        fprintf(f, "address=%s\n", wallet->address);
        fprintf(f, "pubkey=%s\n", wallet->public_key_hex);
        fprintf(f, "privkey=%s\n", wallet->private_key_hex);
        fprintf(f, "device_pub=%s\n", device->pub_hex);
        fprintf(f, "device_priv=%s\n", device->priv_hex);
        fprintf(f, "device_id=%s\n", device->device_id);
        fclose(f);
        printf("Identidade salva em %s\n", identity_file);
        printf("\n⚠️  IMPORTANTE: Guarde este arquivo em local seguro!\n");
        printf("Perder estas chaves significa perder acesso ao histórico de chats.\n\n");
    }
    
    return 0;
}

void print_usage(const char* prog_name) {
    printf("Uso: %s [opções]\n", prog_name);
    printf("\nOpções:\n");
    printf("  --url URL          URL do WebSocket (default: wss://staging.evergram.app/api/ws)\n");
    printf("  --name NOME        Nome do bot (default: EchoBot)\n");
    printf("  --identity ARQ     Arquivo de identidade (default: identity.json)\n");
    printf("  --help             Mostrar esta ajuda\n");
    printf("\nExemplo:\n");
    printf("  %s --url wss://staging.evergram.app/api/ws --name MeuBot\n", prog_name);
}

int main(int argc, char* argv[]) {
    // Configurações padrão
    const char* ws_url = "wss://staging.evergram.app/api/ws";
    const char* bot_name = "EchoBot";
    const char* identity_file = "identity.json";
    
    // Parse de argumentos
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--url") == 0 && i + 1 < argc) {
            ws_url = argv[++i];
        } else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc) {
            bot_name = argv[++i];
        } else if (strcmp(argv[i], "--identity") == 0 && i + 1 < argc) {
            identity_file = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }
    
    printf("=== Evergram C SDK - Echo Bot ===\n");
    printf("URL: %s\n", ws_url);
    printf("Nome: %s\n", bot_name);
    printf("\n");
    
    // Configurar handler de sinal
    signal(SIGINT, handle_sigint);
    
    // Carregar ou criar identidade
    evergram_wallet_t wallet;
    evergram_device_t device;
    memset(&wallet, 0, sizeof(wallet));
    memset(&device, 0, sizeof(device));
    
    int result = load_or_create_identity(&wallet, &device, identity_file);
    if (result < 0) {
        fprintf(stderr, "Falha ao carregar/criar identidade\n");
        return 1;
    }
    
    printf("Carteira: %s\n", wallet.address);
    printf("Device ID: %s\n", device.device_id);
    printf("\n");
    
    // Configurar bot
    evergram_options_t options = {
        .url = ws_url,
        .wallet = &wallet,
        .device = &device,
        .name = bot_name,
        .platform = "Terminal",
        .max_participants = 250,
        .request_timeout_ms = 30000,
        .auto_reconnect = true,
        .user_data = &wallet
    };
    
    // Criar instância
    evergram_t* bot = evergram_create(&options);
    if (!bot) {
        fprintf(stderr, "Falha ao criar instância do Evergram\n");
        return 1;
    }
    
    // Registrar callbacks
    evergram_on_message(bot, on_message);
    evergram_on_reaction(bot, on_reaction);
    evergram_on_typing(bot, on_typing);
    evergram_on_error(bot, on_error);
    evergram_on_connected(bot, on_connected);
    evergram_on_disconnected(bot, on_disconnected);
    
    // Iniciar conexão
    printf("Conectando ao Evergram...\n");
    int ret = evergram_start(bot);
    if (ret != EVERGRAM_SUCCESS) {
        fprintf(stderr, "Falha ao conectar: %s\n", evergram_strerror(ret));
        evergram_destroy(bot);
        return 1;
    }
    
    printf("Pressione Ctrl+C para sair.\n\n");
    
    // Loop principal
    while (running) {
        // Processar eventos por 100ms
        ret = evergram_poll(bot, 100);
        if (ret != EVERGRAM_SUCCESS && ret != EVERGRAM_ERR_TIMEOUT) {
            fprintf(stderr, "Erro no poll: %s\n", evergram_strerror(ret));
            break;
        }
    }
    
    // Cleanup
    printf("\nDesconectando...\n");
    evergram_destroy(bot);
    printf("Tchau!\n");
    
    return 0;
}
