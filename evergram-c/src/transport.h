/**
 * @file transport.h
 * @brief Interface interna do transporte WebSocket
 */

#ifndef EVERGRAM_TRANSPORT_H
#define EVERGRAM_TRANSPORT_H

#include "evergram.h"

// Tipo opaco do transporte
typedef struct ws_transport ws_transport_t;

/**
 * @brief Inicializa o transporte WebSocket
 * @param eg Ponteiro para contexto Evergram
 * @param url URL do servidor WebSocket
 * @return Ponteiro para transporte ou NULL em erro
 */
ws_transport_t* transport_init(evergram_t* eg, const char* url);

/**
 * @brief Conecta ao servidor WebSocket
 * @param transport Ponteiro para transporte
 * @param host Hostname do servidor
 * @param port Porta do servidor
 * @param use_ssl 1 para SSL/TLS, 0 para conexão simples
 * @param path Path da URL WebSocket
 * @return EVERGRAM_SUCCESS ou erro
 */
int transport_connect(ws_transport_t* transport, const char* host, int port, 
                     int use_ssl, const char* path);

/**
 * @brief Envia dados através do WebSocket
 * @param transport Ponteiro para transporte
 * @param data Dados a enviar
 * @param len Tamanho dos dados
 * @return EVERGRAM_SUCCESS ou erro
 */
int transport_send(ws_transport_t* transport, const uint8_t* data, size_t len);

/**
 * @brief Processa eventos do WebSocket
 * @param transport Ponteiro para transporte
 * @param timeout_ms Timeout em milissegundos
 * @return EVERGRAM_SUCCESS ou erro
 */
int transport_poll(ws_transport_t* transport, int timeout_ms);

/**
 * @brief Fecha e libera o transporte
 * @param transport Ponteiro para transporte
 */
void transport_destroy(ws_transport_t* transport);

/**
 * @brief Verifica se está conectado
 * @param transport Ponteiro para transporte
 * @return 1 se conectado, 0 caso contrário
 */
int transport_is_connected(ws_transport_t* transport);

/**
 * @brief Obtém estado atual do transporte
 * @param transport Ponteiro para transporte
 * @return Estado atual
 */
evergram_state_t transport_get_state(ws_transport_t* transport);

#endif // EVERGRAM_TRANSPORT_H
