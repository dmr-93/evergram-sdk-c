/*
 * regular-key-auth-check — one-off manual check for RegularKey auth.
 *
 * Port of examples/regular-key-auth-check/index.ts. It only connects and
 * reports whether the gateway accepted the signature; there is no bot logic
 * and no persisted identity (the device is ephemeral on purpose).
 *
 *   ACCOUNT_ADDRESS=r...            account being authenticated as
 *   REGULAR_KEY_SEED=sEd...         seed of that account's RegularKey
 *   EVERGRAM_GATEWAY_URL=wss://...  defaults to ws://localhost:9000/api/ws
 *
 * Prerequisites on the account: it must exist on-ledger with a SetRegularKey
 * transaction pointing at the key whose seed is REGULAR_KEY_SEED.
 */

#include <evergram.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define POLL_INTERVAL_MS 100
#define POLL_ROUNDS 150 /* ~15s to authenticate or give up */

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_authenticated = 0;
static volatile sig_atomic_t g_failed = 0;

static void on_signal(int number) {
    (void)number;
    g_running = 0;
}

static void on_connected(evergram_t *eg) {
    (void)eg;
    printf("[regular-key-auth-check] AUTH OK — gateway accepted the RegularKey signature.\n");
    g_authenticated = 1;
    g_running = 0;
}

static void on_error(evergram_t *eg, evergram_status_t status, const char *detail) {
    (void)eg;
    fprintf(stderr, "[regular-key-auth-check] AUTH FAILED: %s%s%s\n",
            evergram_status_str(status), detail != NULL ? " — " : "",
            detail != NULL ? detail : "");
    g_failed = 1;
    g_running = 0;
}

static void on_disconnected(evergram_t *eg) {
    (void)eg;
    if (!g_authenticated) {
        fprintf(stderr, "[regular-key-auth-check] connection closed before authentication\n");
        g_failed = 1;
        g_running = 0;
    }
}

int main(void) {
    const char *gateway = getenv("EVERGRAM_GATEWAY_URL");
    const char *account = getenv("ACCOUNT_ADDRESS");
    const char *regular_key_seed = getenv("REGULAR_KEY_SEED");

    if (gateway == NULL || gateway[0] == '\0') {
        gateway = "ws://localhost:9000/api/ws";
    }
    if (account == NULL || account[0] == '\0' || regular_key_seed == NULL ||
        regular_key_seed[0] == '\0') {
        fprintf(stderr,
                "[regular-key-auth-check] Set ACCOUNT_ADDRESS and REGULAR_KEY_SEED before "
                "running.\n");
        return 1;
    }

    evergram_wallet_t wallet;
    evergram_device_t device;
    evergram_status_t status = evergram_wallet_from_regular_key(account, regular_key_seed,
                                                               &wallet);
    if (status != EVERGRAM_OK) {
        fprintf(stderr, "[regular-key-auth-check] bad RegularKey material: %s\n",
                evergram_status_str(status));
        return 1;
    }

    status = evergram_device_generate(&device);
    if (status != EVERGRAM_OK) {
        fprintf(stderr, "[regular-key-auth-check] cannot generate a device: %s\n",
                evergram_status_str(status));
        evergram_wallet_wipe(&wallet);
        return 1;
    }

    printf("[regular-key-auth-check] account:     %s\n", wallet.address);
    printf("[regular-key-auth-check] signing key: %s (RegularKey)\n", wallet.public_key_hex);
    printf("[regular-key-auth-check] gateway:     %s\n", gateway);

    const evergram_options_t options = {
        .url = gateway,
        .wallet = &wallet,
        .device = &device,
        .platform = "Terminal",
    };

    evergram_t *client = evergram_create(&options);
    if (client == NULL) {
        fprintf(stderr, "[regular-key-auth-check] cannot create the client\n");
        evergram_wallet_wipe(&wallet);
        evergram_device_wipe(&device);
        return 1;
    }

    evergram_on_connected(client, on_connected);
    evergram_on_error(client, on_error);
    evergram_on_disconnected(client, on_disconnected);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    status = evergram_start(client);
    if (status != EVERGRAM_OK) {
        fprintf(stderr, "[regular-key-auth-check] cannot connect: %s\n",
                evergram_status_str(status));
        evergram_destroy(client);
        evergram_wallet_wipe(&wallet);
        evergram_device_wipe(&device);
        return 1;
    }

    for (int round = 0; g_running && round < POLL_ROUNDS; round++) {
        evergram_poll(client, POLL_INTERVAL_MS);
    }

    int exit_code = g_authenticated ? 0 : 1;
    if (!g_authenticated && !g_failed) {
        fprintf(stderr, "[regular-key-auth-check] timed out waiting for authentication\n");
    }

    evergram_destroy(client);
    evergram_wallet_wipe(&wallet);
    evergram_device_wipe(&device);
    return exit_code;
}
