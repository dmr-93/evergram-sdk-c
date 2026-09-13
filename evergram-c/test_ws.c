#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <libwebsockets.h>

static int running = 1;

void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}

static int callback(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
    fprintf(stderr, "[WS] Callback: reason=%d\\n", reason);
    
    switch (reason) {
        case LWS_CALLBACK_ESTABLISHED:
            fprintf(stderr, "[WS] Conexão estabelecida!\\n");
            break;
        case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
            fprintf(stderr, "[WS] Erro: %s\\n", in ? (const char*)in : "unknown");
            break;
        case LWS_CALLBACK_CLIENT_RECEIVE:
            fprintf(stderr, "[WS] Recebido %zu bytes\\n", len);
            break;
        case LWS_CALLBACK_CLOSED:
            fprintf(stderr, "[WS] Conexão fechada\\n");
            running = 0;
            break;
        default:
            break;
    }
    
    return 0;
}

static struct lws_protocols protocols[] = {
    { "evergram-protocol", callback, 0, 0, 0, NULL, 0 },
    { NULL, NULL, 0, 0, 0, NULL, 0 }
};

int main() {
    fprintf(stderr, "[WS] Criando contexto...\\n");
    
    struct lws_context_creation_info info;
    memset(&info, 0, sizeof(info));
    info.port = CONTEXT_PORT_NO_LISTEN;
    info.protocols = protocols;
    info.gid = -1;
    info.uid = -1;
    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
    info.timeout_secs = 10;
    
    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        fprintf(stderr, "[WS] Falha ao criar contexto!\\n");
        return 1;
    }
    
    fprintf(stderr, "[WS] Conectando a staging.evergram.app:443/ws...\\n");
    
    struct lws_client_connect_info ccinfo;
    memset(&ccinfo, 0, sizeof(ccinfo));
    ccinfo.context = context;
    ccinfo.address = "staging.evergram.app";
    ccinfo.port = 443;
    ccinfo.path = "/ws";
    ccinfo.host = "staging.evergram.app";
    ccinfo.origin = "staging.evergram.app";
    ccinfo.protocol = protocols[0].name;
    ccinfo.ssl_connection = 2;
    
    struct lws *wsi = lws_client_connect_via_info(&ccinfo);
    if (!wsi) {
        fprintf(stderr, "[WS] Falha ao conectar!\\n");
        lws_context_destroy(context);
        return 1;
    }
    
    fprintf(stderr, "[WS] Aguardando eventos...\\n");
    
    signal(SIGINT, handle_sigint);
    
    while (running) {
        lws_service(context, 100);
    }
    
    fprintf(stderr, "[WS] Finalizando...\\n");
    lws_context_destroy(context);
    fprintf(stderr, "[WS] Teste concluido!\\n");
    return 0;
}
