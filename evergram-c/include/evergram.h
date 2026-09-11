#ifndef EVERGRAM_H
#define EVERGRAM_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Define para habilitar strdup e outras funções POSIX
#define _POSIX_C_SOURCE 200809L

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// Constantes e Limites
// ============================================================================

#define EVERGRAM_MAX_ADDRESS_LEN      64
#define EVERGRAM_MAX_HEX_KEY_LEN      128
#define EVERGRAM_MAX_DEVICE_ID_LEN    64
#define EVERGRAM_MAX_MESSAGE_LEN      10000
#define EVERGRAM_MAX_CHAT_ID_LEN      128
#define EVERGRAM_MAX_IDENTITY_KEY_LEN 128
#define EVERGRAM_MAX_NAME_LEN         128
#define EVERGRAM_MAX_NONCE_LEN        64

// ============================================================================
// Códigos de Erro
// ============================================================================

typedef enum {
    EVERGRAM_SUCCESS = 0,
    EVERGRAM_ERR_INVALID_PARAM = -1,
    EVERGRAM_ERR_MEMORY = -2,
    EVERGRAM_ERR_CRYPTO = -3,
    EVERGRAM_ERR_NETWORK = -4,
    EVERGRAM_ERR_AUTH = -5,
    EVERGRAM_ERR_TIMEOUT = -6,
    EVERGRAM_ERR_PROTO = -7,
    EVERGRAM_ERR_NOT_CONNECTED = -8,
    EVERGRAM_ERR_RATE_LIMITED = -9,
    EVERGRAM_ERR_ACCESS_DENIED = -10,
    EVERGRAM_ERR_NOT_FOUND = -11,
    EVERGRAM_ERR_ROTATION_REQUIRED = -12,
    EVERGRAM_ERR_DEVICE_REVOKED = -13,
    EVERGRAM_ERR_INSUFFICIENT_BALANCE = -14,
    EVERGRAM_ERR_UNKNOWN = -99
} evergram_error_t;

// ============================================================================
// Tipos de Dados
// ============================================================================

// Carteira XRPL
typedef struct {
    char seed[EVERGRAM_MAX_HEX_KEY_LEN];
    char address[EVERGRAM_MAX_ADDRESS_LEN];
    char public_key_hex[EVERGRAM_MAX_HEX_KEY_LEN];
    char private_key_hex[EVERGRAM_MAX_HEX_KEY_LEN];
} evergram_wallet_t;

// Dispositivo E2EE
typedef struct {
    char device_id[EVERGRAM_MAX_DEVICE_ID_LEN];
    char pub_hex[EVERGRAM_MAX_HEX_KEY_LEN];
    char priv_hex[EVERGRAM_MAX_HEX_KEY_LEN];
} evergram_device_t;

// Mensagem de chat recebida
typedef struct evergram_message {
    char chat_id[EVERGRAM_MAX_CHAT_ID_LEN];
    char sender[EVERGRAM_MAX_IDENTITY_KEY_LEN];
    char msg_id[EVERGRAM_MAX_HEX_KEY_LEN];
    uint64_t timestamp;
    char* text;  // Pode ser NULL para mensagens não-texto
    char* reply_to_msg_id;  // NULL se não for resposta
    struct evergram_message* next;  // Para listas encadeadas
} evergram_message_t;

// Reação a mensagem
typedef struct {
    char chat_id[EVERGRAM_MAX_CHAT_ID_LEN];
    char sender[EVERGRAM_MAX_IDENTITY_KEY_LEN];
    char msg_id[EVERGRAM_MAX_HEX_KEY_LEN];
    char emoji[16];  // Emoji ou NULL se removida
    bool removed;
    uint64_t timestamp;
} evergram_reaction_t;

// Evento de digitação
typedef struct {
    char chat_id[EVERGRAM_MAX_CHAT_ID_LEN];
    char sender[EVERGRAM_MAX_IDENTITY_KEY_LEN];
    bool is_typing;
    uint64_t timestamp;
} evergram_typing_event_t;

// Informações do chat
typedef struct {
    char chat_id[EVERGRAM_MAX_CHAT_ID_LEN];
    char name[EVERGRAM_MAX_NAME_LEN];
    bool is_group;
    int participant_count;
    char** participants;  // Array de identity keys
    int participant_count_allocated;
} evergram_chat_info_t;

// Perfil de usuário
typedef struct {
    char identity_key[EVERGRAM_MAX_IDENTITY_KEY_LEN];
    char name[EVERGRAM_MAX_NAME_LEN];
    char bio[512];
} evergram_profile_t;

// Opções de configuração
typedef struct {
    const char* url;              // URL WebSocket (obrigatório)
    evergram_wallet_t* wallet;    // Carteira XRPL (obrigatório)
    evergram_device_t* device;    // Dispositivo E2EE (obrigatório)
    const char* name;             // Nome do bot (opcional)
    const char* platform;         // Plataforma (opcional, default: "Terminal")
    int max_participants;         // Máximo participantes (default: 250)
    int request_timeout_ms;       // Timeout em ms (default: 30000)
    bool auto_reconnect;          // Reconectar automaticamente (default: true)
    void* user_data;              // Dados do usuário para callbacks
} evergram_options_t;

// Instância principal do Evergram (opaca)
typedef struct evergram evergram_t;

// ============================================================================
// Callbacks
// ============================================================================

typedef void (*evergram_message_callback)(evergram_t* eg, const evergram_message_t* msg);
typedef void (*evergram_reaction_callback)(evergram_t* eg, const evergram_reaction_t* reaction);
typedef void (*evergram_typing_callback)(evergram_t* eg, const evergram_typing_event_t* event);
typedef void (*evergram_error_callback)(evergram_t* eg, evergram_error_t error, const char* message);
typedef void (*evergram_connected_callback)(evergram_t* eg);
typedef void (*evergram_disconnected_callback)(evergram_t* eg);
typedef void (*evergram_chat_synced_callback)(evergram_t* eg, const evergram_chat_info_t* chat);

// ============================================================================
// Funções de Inicialização
// ============================================================================

/**
 * Gera uma nova carteira XRPL aleatória.
 * @param wallet Ponteiro para estrutura a ser preenchida
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_generate_wallet(evergram_wallet_t* wallet);

/**
 * Cria carteira a partir de seed existente.
 * @param wallet Ponteiro para estrutura a ser preenchida
 * @param seed Seed da carteira (hex string)
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_wallet_from_seed(evergram_wallet_t* wallet, const char* seed);

/**
 * Gera par de chaves do dispositivo E2EE.
 * @param device Ponteiro para estrutura a ser preenchida
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_generate_device(evergram_device_t* device);

/**
 * Deriva device_id a partir da chave pública.
 * @param device_pub_hex Chave pública em hex
 * @param device_id_out Buffer para output (min EVERGRAM_MAX_DEVICE_ID_LEN)
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_derive_device_id(const char* device_pub_hex, char* device_id_out);

/**
 * Converte string hex para bytes.
 * @param hex String hex de entrada
 * @param out Buffer de saída
 * @param out_len Tamanho do buffer de saída
 * @return Número de bytes escritos ou erro negativo
 */
int evergram_hex_to_bytes(const char* hex, uint8_t* out, size_t out_len);

/**
 * Converte bytes para string hex.
 * @param bytes Buffer de entrada
 * @param len Número de bytes
 * @param out Buffer de saída (deve ter espaço para 2*len + 1)
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_bytes_to_hex(const uint8_t* bytes, size_t len, char* out, size_t out_len);

// ============================================================================
// Gerenciamento da Instância
// ============================================================================

/**
 * Cria nova instância do Evergram.
 * @param options Configurações
 * @return Ponteiro para instância ou NULL em erro
 */
evergram_t* evergram_create(const evergram_options_t* options);

/**
 * Inicia conexão com o gateway.
 * @param eg Instância do Evergram
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_start(evergram_t* eg);

/**
 * Processa eventos por um período determinado.
 * Deve ser chamado periodicamente no loop principal.
 * @param eg Instância do Evergram
 * @param timeout_ms Tempo máximo para bloquear (ms)
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_poll(evergram_t* eg, int timeout_ms);

/**
 * Verifica se está conectado.
 * @param eg Instância do Evergram
 * @return true se conectado
 */
bool evergram_is_connected(evergram_t* eg);

/**
 * Libera todos os recursos.
 * @param eg Instância do Evergram
 */
void evergram_destroy(evergram_t* eg);

// ============================================================================
// Registro de Callbacks
// ============================================================================

/**
 * Registra callback para mensagens recebidas.
 * @param eg Instância do Evergram
 * @param cb Função callback
 */
void evergram_on_message(evergram_t* eg, evergram_message_callback cb);

/**
 * Registra callback para reações.
 * @param eg Instância do Evergram
 * @param cb Função callback
 */
void evergram_on_reaction(evergram_t* eg, evergram_reaction_callback cb);

/**
 * Registra callback para eventos de digitação.
 * @param eg Instância do Evergram
 * @param cb Função callback
 */
void evergram_on_typing(evergram_t* eg, evergram_typing_callback cb);

/**
 * Registra callback para erros.
 * @param eg Instância do Evergram
 * @param cb Função callback
 */
void evergram_on_error(evergram_t* eg, evergram_error_callback cb);

/**
 * Registra callback para conexão estabelecida.
 * @param eg Instância do Evergram
 * @param cb Função callback
 */
void evergram_on_connected(evergram_t* eg, evergram_connected_callback cb);

/**
 * Registra callback para desconexão.
 * @param eg Instância do Evergram
 * @param cb Função callback
 */
void evergram_on_disconnected(evergram_t* eg, evergram_disconnected_callback cb);

/**
 * Registra callback para chat sincronizado.
 * @param eg Instância do Evergram
 * @param cb Função callback
 */
void evergram_on_chat_synced(evergram_t* eg, evergram_chat_synced_callback cb);

// ============================================================================
// Envio de Mensagens
// ============================================================================

/**
 * Responde a uma mensagem específica.
 * @param eg Instância do Evergram
 * @param reply_to Mensagem original sendo respondida
 * @param format String de formato (printf-style)
 * @param ... Argumentos variádicos
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_reply(evergram_t* eg, const evergram_message_t* reply_to, 
                   const char* format, ...);

/**
 * Envia mensagem para um chat.
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @param text Texto da mensagem
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_send(evergram_t* eg, const char* chat_id, const char* text);

/**
 * Envia mensagem formatada para um chat.
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @param format String de formato (printf-style)
 * @param ... Argumentos variádicos
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_sendf(evergram_t* eg, const char* chat_id, const char* format, ...);

/**
 * Envia indicador de digitação.
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_send_typing(evergram_t* eg, const char* chat_id);

/**
 * Envia reação a uma mensagem.
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @param msg_id ID da mensagem
 * @param emoji Emoji da reação
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_send_reaction(evergram_t* eg, const char* chat_id, 
                           const char* msg_id, const char* emoji);

/**
 * Remove reação.
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @param msg_id ID da mensagem
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_remove_reaction(evergram_t* eg, const char* chat_id, const char* msg_id);

/**
 * Edita mensagem enviada.
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @param msg_id ID da mensagem
 * @param new_text Novo texto
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_edit_message(evergram_t* eg, const char* chat_id, 
                          const char* msg_id, const char* new_text);

/**
 * Deleta mensagem.
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @param msg_id ID da mensagem
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_delete_message(evergram_t* eg, const char* chat_id, const char* msg_id);

// ============================================================================
// Gerenciamento de Chats
// ============================================================================

/**
 * Cria novo chat 1-1.
 * @param eg Instância do Evergram
 * @param identity_key Identity key do destinatário
 * @param chat_id_out Buffer para output do chat_id (pode ser NULL)
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_create_chat(evergram_t* eg, const char* identity_key, char* chat_id_out);

/**
 * Cria grupo.
 * @param eg Instância do Evergram
 * @param name Nome do grupo
 * @param participant_keys Array de identity keys
 * @param participant_count Número de participantes
 * @param chat_id_out Buffer para output do chat_id (pode ser NULL)
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_create_group(evergram_t* eg, const char* name,
                          const char** participant_keys, int participant_count,
                          char* chat_id_out);

/**
 * Adiciona participante ao grupo.
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @param identity_key Identity key do novo participante
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_add_participant(evergram_t* eg, const char* chat_id, 
                             const char* identity_key);

/**
 * Remove participante do grupo.
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @param identity_key Identity key do participante
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_remove_participant(evergram_t* eg, const char* chat_id, 
                                const char* identity_key);

/**
 * Sai de um chat/grupo.
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_leave_chat(evergram_t* eg, const char* chat_id);

/**
 * Rotação da chave do chat (necessário para novos dispositivos).
 * @param eg Instância do Evergram
 * @param chat_id ID do chat
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_rotate_chat_version(evergram_t* eg, const char* chat_id);

// ============================================================================
// Consultas e Informações
// ============================================================================

/**
 * Obtém perfil de usuário.
 * @param eg Instância do Evergram
 * @param identity_key Identity key do usuário
 * @param profile_out Estrutura para preencher
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_get_profile(evergram_t* eg, const char* identity_key, 
                         evergram_profile_t* profile_out);

/**
 * Atualiza próprio perfil.
 * @param eg Instância do Evergram
 * @param name Novo nome (pode ser NULL)
 * @param bio Nova bio (pode ser NULL)
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_set_profile(evergram_t* eg, const char* name, const char* bio);

/**
 * Lista chats conhecidos.
 * @param eg Instância do Evergram
 * @param chats_out Array de ponteiros para evergram_chat_info_t
 * @param max_chats Tamanho máximo do array
 * @return Número de chats ou erro negativo
 */
int evergram_list_chats(evergram_t* eg, evergram_chat_info_t** chats_out, int max_chats);

/**
 * Libera informações de chat.
 * @param chat Ponteiro para estrutura de chat
 */
void evergram_free_chat_info(evergram_chat_info_t* chat);

// ============================================================================
// Utilitários
// ============================================================================

/**
 * Obtém código de erro como string legível.
 * @param error Código de erro
 * @return String descritiva
 */
const char* evergram_strerror(evergram_error_t error);

/**
 * Define dados do usuário (acessíveis via eg->user_data nos callbacks).
 * @param eg Instância do Evergram
 * @param user_data Ponteiro para dados do usuário
 */
void evergram_set_user_data(evergram_t* eg, void* user_data);

/**
 * Obtém dados do usuário.
 * @param eg Instância do Evergram
 * @return Ponteiro para dados do usuário
 */
void* evergram_get_user_data(evergram_t* eg);

/**
 * Versão da biblioteca.
 * @return String de versão
 */
const char* evergram_version(void);

#ifdef __cplusplus
}
#endif

#endif // EVERGRAM_H
