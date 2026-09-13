# Evergram SDK for C

Portagem standalone do [Evergram SDK](https://github.com/rosseti/evergram-sdk) para C, permitindo integração de bots e aplicações com o protocolo Evergram de mensagens descentralizadas e criptografadas de ponta-a-ponta.

## Visão Geral

Este SDK fornece:

- **Autenticação via carteira XRPL** - Assinatura de desafios criptográficos
- **Comunicação WebSocket** - Conexão com o gateway Evergram
- **Criptografia E2EE** - Usando libsodium (compatível com tweetnacl do SDK original)
- **Serialização Protobuf** - Mensagens no formato do protocolo Evergram
- **API simplificada** - Interface C idiomática para bots

## Estrutura do Projeto

```
evergram-c/
├── include/
│   └── evergram.h          # API pública principal
├── src/
│   ├── evergram.c          # Implementação principal
│   ├── crypto.c            # Primitivas criptográficas
│   ├── wallet.c            # Gerenciamento de carteira XRPL
│   ├── transport.c         # Transporte WebSocket
│   └── proto.c             # Serialização protobuf (básica)
├── examples/
│   └── echo-bot.c          # Exemplo de bot simples
├── Makefile                # Build system
└── README.md               # Este arquivo
```

## Dependências

- **libsodium** - Criptografia (compatible com tweetnacl)
- **libwebsockets** ou **libuv + libwebsocket** - Transporte WebSocket
- **protobuf-c** - Serialização de mensagens
- **ripple-keypairs** (via bindings C) - Chaves XRPL

### Instalação das dependências (Ubuntu/Debian)

```bash
sudo apt-get install libsodium-dev libwebsockets-dev protobuf-c-compiler libprotobuf-c-dev
```

## Quick Start

```c
#include <evergram.h>
#include <stdio.h>
#include <stdlib.h>

// Callback para mensagens recebidas
void on_message(evergram_t* eg, const evergram_message_t* msg) {
    if (msg->text) {
        printf("Mensagem recebida: %s\n", msg->text);
        
        // Responder automaticamente
        evergram_reply(eg, msg, "Você disse: %s", msg->text);
    }
}

int main() {
    // Gerar identidade (fazer isso uma vez e persistir)
    evergram_wallet_t wallet;
    evergram_device_t device;
    
    evergram_generate_wallet(&wallet);
    evergram_generate_device(&device);
    
    // Persistir wallet.seed e device.priv_hex para reuso
    
    // Configurar bot
    evergram_t* bot = evergram_create(&(evergram_options_t){
        .url = "ws://localhost:9000/api/ws",
        .wallet = &wallet,
        .device = &device,
        .name = "MeuBotC"
    });
    
    // Registrar callback
    evergram_on_message(bot, on_message);
    
    // Conectar e iniciar
    if (evergram_start(bot) != EVERGRAM_SUCCESS) {
        fprintf(stderr, "Falha ao conectar\n");
        return 1;
    }
    
    printf("Online como %s\n", wallet.address);
    
    // Loop principal (em produção, usar event loop adequado)
    while (1) {
        evergram_poll(bot, 1000);  // Processar eventos por 1 segundo
    }
    
    evergram_destroy(bot);
    return 0;
}
```

## Compilação

```bash
make
```

Ou manualmente:

```bash
gcc -I./include -o echo-bot examples/echo-bot.c src/*.c \
    -lsodium -lwebsockets -lprotobuf-c -lcurl
```

## Exemplos

Veja `examples/echo-bot.c` para um exemplo completo de bot que responde mensagens.

## API Principal

### Inicialização

```c
// Gerar nova carteira XRPL
int evergram_generate_wallet(evergram_wallet_t* wallet);

// Gerar par de chaves do dispositivo
int evergram_generate_device(evergram_device_t* device);

// Criar instância do Evergram
evergram_t* evergram_create(const evergram_options_t* options);

// Iniciar conexão
int evergram_start(evergram_t* eg);

// Processar eventos (chamar periodicamente)
int evergram_poll(evergram_t* eg, int timeout_ms);

// Limpar recursos
void evergram_destroy(evergram_t* eg);
```

### Callbacks

```c
// Registrar callbacks
void evergram_on_message(evergram_t* eg, evergram_message_callback cb);
void evergram_on_reaction(evergram_t* eg, evergram_reaction_callback cb);
void evergram_on_error(evergram_t* eg, evergram_error_callback cb);
```

### Envio de Mensagens

```c
// Responder a uma mensagem
int evergram_reply(evergram_t* eg, const evergram_message_t* reply_to, 
                   const char* format, ...);

// Enviar mensagem para um chat
int evergram_send(evergram_t* eg, const char* chat_id, const char* text);

// Digitar...
int evergram_send_typing(evergram_t* eg, const char* chat_id);
```

### Gerenciamento de Chats

```c
// Criar novo chat
int evergram_create_chat(evergram_t* eg, const char* identity_key);

// Entrar em grupo
int evergram_join_group(evergram_t* eg, const char* chat_id);

// Sair de chat
int evergram_leave_chat(evergram_t* eg, const char* chat_id);
```

## Segurança

⚠️ **Status Beta**: O caminho de autenticação por assinatura de carteira é novo. Use com cautela em produção.

### Chaves do Dispositivo

O SDK **não persiste chaves automaticamente**. Você deve persistir:
- `wallet.seed` - Seed da carteira XRPL
- `device.pub_hex` e `device.priv_hex` - Chaves do dispositivo E2EE

Perder `device.priv_hex` significa perder acesso ao histórico de chats permanentemente.

### Armazenamento Seguro

Em produção, use:
- Gerenciadores de segredos (HashiCorp Vault, AWS Secrets Manager)
- Volumes criptografados
- HSMs quando disponível

## Limitações Conhecidas

1. **Sem backup de chaves** - Mesma limitação do webapp cliente
2. **Gateway é confiável para chaves de chat** - O gateway gera e vê temporariamente chaves simétricas de chat (veja README original para detalhes)
3. **Rate limiting** - Ações são limitadas por identidade+dispositivo

## Diferenças do SDK TypeScript

| TypeScript SDK | SDK C |
|---------------|-------|
| Classes OO | Structs + funções |
| Promises/async | Callbacks + polling |
| tweetnacl | libsodium |
| ws | libwebsockets |
| protobufjs | protobuf-c |

## Contribuindo

1. Fork o repositório
2. Crie um branch para sua feature
3. Compile sem warnings (`make clean && make`)
4. Teste com valgrind para memory leaks
5. Submit um PR

## Licença

MIT - veja LICENSE para detalhes.

## Links

- [SDK Original (TypeScript)](https://github.com/rosseti/evergram-sdk)
- [Protocolo Evergram](https://github.com/rosseti/evergram-gateway)
- [Documentação XRPL](https://xrpl.org/)
