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

// Include do header gerado pelo protobuf-c (schema real da Evergram)
#include "evergram.pb-c.h"

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
#define EVERGRAM_MAX_NONCE_LEN        24
#define EVERGRAM_DEVICE_KEY_LEN       32
#define EVERGRAM_DEVICE_ID_LEN        16
#define EVERGRAM_SIGNATURE_LEN        64
#define EVERGRAM_MAC_BYTES            16

// URL do servidor de staging
#define EVERGRAM_DEFAULT_HOST         "staging.evergram.app"
#define EVERGRAM_DEFAULT_PORT         443
#define EVERGRAM_DEFAULT_PATH         "/"

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
    EVERGRAM_ERR_BUFFER_TOO_SMALL = -15,
    EVERGRAM_ERR_UNKNOWN = -99
} evergram_error_t;

// ============================================================================
// Tipos de Dados
// ============================================================================

/**
 * @brief Configurações de conexão para a Evergram.
 */
typedef struct {
    const char* host;        /**< Host do servidor (ex: "staging.evergram.app") */
    int port;                /**< Porta (443 para WSS, 80 para WS) */
    int use_ssl;             /**< 1 para WSS (SSL), 0 para WS */
    const char* path;        /**< Path da URL (ex: "/") */
    int timeout_ms;          /**< Timeout de conexão em milissegundos */
} evergram_config_t;

/**
 * @brief Configuração padrão para o servidor de staging.
 */
static inline evergram_config_t evergram_staging_config(void) {
    evergram_config_t cfg;
    cfg.host = EVERGRAM_DEFAULT_HOST;
    cfg.port = EVERGRAM_DEFAULT_PORT;
    cfg.use_ssl = 1;  // WSS
    cfg.path = EVERGRAM_DEFAULT_PATH;
    cfg.timeout_ms = 10000;
    return cfg;
}

/**
 * @brief Estados possíveis da conexão.
 */
typedef enum {
    EVERGRAM_STATE_DISCONNECTED = 0,
    EVERGRAM_STATE_CONNECTING,
    EVERGRAM_STATE_CONNECTED,
    EVERGRAM_STATE_AUTHENTICATING,
    EVERGRAM_STATE_ERROR
} evergram_state_t;

typedef enum {
    EVERGRAM_HS_DISCONNECTED = 0,
    EVERGRAM_HS_CONNECTING,
    EVERGRAM_HS_CLIENT_HELLO_SENT,
    EVERGRAM_HS_SERVER_HELLO_RECEIVED,
    EVERGRAM_HS_KEYS_DERIVED,
    EVERGRAM_HS_AUTHENTICATED,
    EVERGRAM_HS_CONNECTED,
    EVERGRAM_HS_ERROR
} evergram_hs_state_t;

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
 * @brief Inicializa a biblioteca criptográfica (libsodium).
 * @return EVERGRAM_SUCCESS ou erro
 */
evergram_error_t evergram_crypto_init(void);

/**
 * @brief Gera um par de chaves para dispositivo.
 * @param public_key Buffer para chave pública (tamanho: EVERGRAM_DEVICE_KEY_LEN)
 * @param secret_key Buffer para chave secreta (tamanho: EVERGRAM_DEVICE_KEY_LEN)
 * @return EVERGRAM_SUCCESS ou erro
 */
evergram_error_t evergram_generate_device_keys(unsigned char *public_key, unsigned char *secret_key);

/**
 * @brief Gera um nonce aleatório seguro.
 * @param nonce Buffer de saída (tamanho: EVERGRAM_MAX_NONCE_LEN)
 * @return EVERGRAM_SUCCESS ou erro
 */
evergram_error_t evergram_generate_nonce(unsigned char *nonce);

/**
 * @brief Criptografa uma mensagem usando crypto_secretbox.
 */
evergram_error_t evergram_encrypt_message(const unsigned char *plaintext, size_t plaintext_len,
                                          const unsigned char *nonce, const unsigned char *shared_key,
                                          unsigned char *ciphertext, size_t *ciphertext_len);

/**
 * @brief Descriptografa uma mensagem usando crypto_secretbox_open.
 */
evergram_error_t evergram_decrypt_message(const unsigned char *ciphertext, size_t ciphertext_len,
                                          const unsigned char *nonce, const unsigned char *shared_key,
                                          unsigned char *plaintext, size_t *plaintext_len);

/**
 * @brief Assina uma mensagem com a chave secreta do dispositivo.
 */
evergram_error_t evergram_sign_message(const unsigned char *message, size_t message_len,
                                       const unsigned char *secret_key,
                                       unsigned char *signature, size_t *signature_len);

/**
 * @brief Verifica a assinatura de uma mensagem.
 */
evergram_error_t evergram_verify_signature(const unsigned char *message, size_t message_len,
                                           const unsigned char *signature, size_t signature_len,
                                           const unsigned char *public_key);

/**
 * @brief Converte chave pública para formato hexadecimal.
 */
evergram_error_t evergram_key_to_hex(const unsigned char *key, char *hex_output);

/**
 * @brief Converte string hexadecimal para chave binária.
 */
evergram_error_t evergram_hex_to_key(const char *hex_input, unsigned char *key_output);

/**
 * @brief Gera um timestamp Unix em milissegundos.
 */
uint64_t evergram_get_timestamp_ms(void);

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
 * Processa dados de handshake recebidos (uso interno).
 * @param eg Instância do Evergram
 * @param data Dados brutos recebidos
 * @param size Tamanho dos dados
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_process_handshake_data(evergram_t* eg, const uint8_t* data, size_t size);

/**
 * Inicia o protocolo de handshake (uso interno).
 * @param eg Instância do Evergram
 * @return EVERGRAM_SUCCESS ou erro
 */
int evergram_start_handshake(evergram_t* eg);

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
