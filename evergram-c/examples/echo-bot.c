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

// Callback para mensagens recebidas
void on_message(evergram_t* eg, const evergram_message_t* msg) {
    if (!msg || !msg->text) {
        return;
    }
    
    printf("[Mensagem] Chat: %s\n", msg->chat_id);
    printf("[Mensagem] De: %s\n", msg->sender);
    printf("[Mensagem] Texto: %s\n", msg->text);
    
    if (msg->reply_to_msg_id) {
        printf("[Mensagem] Resposta para: %s\n", msg->reply_to_msg_id);
    }
    
    // Ignorar mensagens do próprio bot
    // Em produção, acessar wallet via user_data
    // evergram_wallet_t* wallet = (evergram_wallet_t*)evergram_get_user_data(eg);
    // if (wallet && strcmp(msg->sender, wallet->address) == 0) {
    //     return;
    // }
    
    // Responder com eco
    printf("Respondendo...\n");
    int ret = evergram_reply(eg, msg, "Você disse: %s", msg->text);
    if (ret != EVERGRAM_SUCCESS) {
        fprintf(stderr, "Erro ao responder: %s\n", evergram_strerror(ret));
    }
}

// Callback para reações
void on_reaction(evergram_t* eg, const evergram_reaction_t* reaction) {
    (void)eg;  // Não usado no stub
    if (!reaction) return;
    
    printf("[Reação] Chat: %s, Msg: %s, Emoji: %s, Removida: %s\n",
           reaction->chat_id,
           reaction->msg_id,
           reaction->emoji,
           reaction->removed ? "sim" : "não");
}

// Callback para eventos de digitação
void on_typing(evergram_t* eg, const evergram_typing_event_t* event) {
    (void)eg;  // Não usado no stub
    if (!event) return;
    
    printf("[Digitação] Chat: %s, Usuário: %s, %s digitando\n",
           event->chat_id,
           event->sender,
           event->is_typing ? "está" : "parou de");
}

// Callback para erros
void on_error(evergram_t* eg, evergram_error_t error, const char* message) {
    (void)eg;  // Não usado no stub
    fprintf(stderr, "[ERRO] %s: %s\n", evergram_strerror(error), 
            message ? message : "sem detalhes");
}

// Callback para conexão estabelecida
void on_connected(evergram_t* eg) {
    (void)eg;  // Não usado no stub
    printf("[CONECTADO] Bot online e pronto para receber mensagens!\n");
}

// Callback para desconexão
void on_disconnected(evergram_t* eg) {
    (void)eg;  // Não usado no stub
    printf("[DESCONECTADO] Bot offline.\n");
}

// Função para carregar identidade existente ou criar nova
int load_or_create_identity(evergram_wallet_t* wallet, evergram_device_t* device,
                            const char* identity_file) {
    FILE* f = fopen(identity_file, "r");
    if (f) {
        // Carregar identidade existente
        char line[256];
        
        if (fgets(line, sizeof(line), f)) {
            sscanf(line, "seed=%s", wallet->seed);
        }
        if (fgets(line, sizeof(line), f)) {
            sscanf(line, "address=%s", wallet->address);
        }
        if (fgets(line, sizeof(line), f)) {
            sscanf(line, "pubkey=%s", wallet->public_key_hex);
        }
        if (fgets(line, sizeof(line), f)) {
            sscanf(line, "privkey=%s", wallet->private_key_hex);
        }
        if (fgets(line, sizeof(line), f)) {
            sscanf(line, "device_pub=%s", device->pub_hex);
        }
        if (fgets(line, sizeof(line), f)) {
            sscanf(line, "device_priv=%s", device->priv_hex);
        }
        if (fgets(line, sizeof(line), f)) {
            sscanf(line, "device_id=%s", device->device_id);
        }
        
        fclose(f);
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
    printf("  --url URL          URL do WebSocket (default: ws://localhost:9000/api/ws)\n");
    printf("  --name NOME        Nome do bot (default: EchoBot)\n");
    printf("  --identity ARQ     Arquivo de identidade (default: identity.json)\n");
    printf("  --help             Mostrar esta ajuda\n");
    printf("\nExemplo:\n");
    printf("  %s --url ws://localhost:9000/api/ws --name MeuBot\n", prog_name);
}

int main(int argc, char* argv[]) {
    // Configurações padrão
    const char* ws_url = "ws://localhost:9000/api/ws";
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
        .user_data = NULL
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
