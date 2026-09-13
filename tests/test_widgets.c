#include <string.h>

#include "evergram.h"
#include "evergram.pb-c.h"
#include "internal.h"
#include "test.h"

/*
 * Widgets: the two mappings that make up the wire contract (a config going out,
 * a widget/info record coming in), plus the argument and buffer guards. The
 * calls themselves are request/response round trips that only a live gateway
 * can answer, so what is checked here is everything a gateway cannot change.
 */

/* Only the flagged fields may reach the wire: sending an unset one would clear
 * it, because updateWidgetConfig replaces the stored config. */
static void test_config_fill_sends_only_flagged_fields(void) {
    evergram_widget_config_t config;
    memset(&config, 0, sizeof(config));

    Evergram__WidgetConfig wire;
    evergram_fill_widget_config(&config, &wire);
    CHECK(wire.primary_color == NULL);
    CHECK(wire.logo_url == NULL);
    CHECK(wire.welcome_message == NULL);
    CHECK(wire.input_placeholder == NULL);
    CHECK(wire.agent_name == NULL);
    CHECK(wire.position == NULL);
    CHECK(wire.mode == NULL);
    CHECK(wire.channel_key == NULL);

    config.has_mode = true;
    snprintf(config.mode, sizeof(config.mode), "%s", EVERGRAM_WIDGET_MODE_PUBLIC_GROUP);
    config.has_channel_key = true;
    memset(config.channel_key, 'a', 64);
    config.channel_key[64] = '\0';

    evergram_fill_widget_config(&config, &wire);
    CHECK_EQ_STR(wire.mode, "public_group");
    CHECK_EQ_STR(wire.channel_key, config.channel_key);
    CHECK(wire.agent_name == NULL); /* still not requested */

    /* A NULL config is "change nothing", not a crash. */
    evergram_fill_widget_config(NULL, &wire);
    CHECK(wire.mode == NULL);
}

/* Everything a widget record carries has to survive the mapping, including the
 * optional config the owner's own list response includes. */
static void test_widget_from_proto(void) {
    Evergram__WidgetConfig wire_config = EVERGRAM__WIDGET_CONFIG__INIT;
    wire_config.primary_color = (char *)"#112233";
    wire_config.welcome_message = (char *)"Hi there!";
    wire_config.position = (char *)"bottom-left";
    wire_config.mode = (char *)"public_group";
    wire_config.channel_key = (char *)"deadbeef";

    Evergram__Widget wire_widget = EVERGRAM__WIDGET__INIT;
    wire_widget.widget_id = (char *)"widget-1";
    wire_widget.name = (char *)"Support";
    wire_widget.has_enabled = 1;
    wire_widget.enabled = 1;
    wire_widget.has_deleted = 1;
    wire_widget.deleted = 0;
    wire_widget.has_widget_version = 1;
    wire_widget.widget_version = 7;
    wire_widget.has_created_at = 1;
    wire_widget.created_at = 1700000000000;
    wire_widget.config = &wire_config;

    evergram_widget_t record;
    evergram_widget_from_proto(&wire_widget, &record);

    CHECK_EQ_STR(record.widget_id, "widget-1");
    CHECK_EQ_STR(record.name, "Support");
    CHECK(record.enabled);
    CHECK(!record.deleted);
    CHECK_EQ_INT((long long)record.widget_version, 7LL);
    CHECK_EQ_INT((long long)record.created_at_ms, 1700000000000LL);
    CHECK(record.has_config);
    CHECK(record.config.has_primary_color);
    CHECK_EQ_STR(record.config.primary_color, "#112233");
    CHECK_EQ_STR(record.config.welcome_message, "Hi there!");
    CHECK(record.config.has_position);
    CHECK_EQ_STR(record.config.position, "bottom-left");
    CHECK(record.config.has_channel_key);
    CHECK_EQ_STR(record.config.channel_key, "deadbeef");
    /* A field the gateway did not send stays unset rather than empty-but-set. */
    CHECK(!record.config.has_logo_url);
    CHECK(!record.config.has_agent_name);

    /* A widget without config, or no widget at all, is still safe to read. */
    wire_widget.config = NULL;
    evergram_widget_from_proto(&wire_widget, &record);
    CHECK(!record.has_config);
    CHECK_EQ_STR(record.widget_id, "widget-1");

    evergram_widget_from_proto(NULL, &record);
    CHECK_EQ_STR(record.widget_id, "");
    evergram_widget_from_proto(&wire_widget, NULL); /* must not crash */
}

static void test_widget_info_from_proto(void) {
    Evergram__Device device = EVERGRAM__DEVICE__INIT;
    device.device_id = (char *)"device-1";
    Evergram__Device *devices[1] = {&device};

    Evergram__WidgetConfig config = EVERGRAM__WIDGET_CONFIG__INIT;
    config.agent_name = (char *)"Agent";
    config.mode = (char *)"private_chat";

    Evergram__GetWidgetInfoResponse response = EVERGRAM__GET_WIDGET_INFO_RESPONSE__INIT;
    response.has_enabled = 1;
    response.enabled = 1;
    response.owner_identity_key = (char *)"1:rOwner";
    response.n_devices = 1;
    response.devices = devices;
    response.config = &config;
    response.widget_id = (char *)"widget-1";

    evergram_widget_info_t info;
    evergram_widget_info_from_proto(&response, &info);
    CHECK_EQ_STR(info.widget_id, "widget-1");
    CHECK_EQ_STR(info.owner_identity_key, "1:rOwner");
    CHECK(info.enabled);
    CHECK_EQ_INT((long long)info.device_count, 1LL);
    CHECK(info.has_config);
    CHECK_EQ_STR(info.config.agent_name, "Agent");
    CHECK_EQ_STR(info.config.mode, "private_chat");
    CHECK(!info.config.has_channel_key);

    evergram_widget_info_from_proto(NULL, &info);
    CHECK_EQ_STR(info.widget_id, "");
    CHECK_EQ_INT((long long)info.device_count, 0LL);
    evergram_widget_info_from_proto(&response, NULL); /* must not crash */
}

static void test_widget_call_validation(void) {
    evergram_t *client = NULL;
    evergram_wallet_t wallet;
    evergram_device_t device;
    memset(&wallet, 0, sizeof(wallet));
    memset(&device, 0, sizeof(device));

    if (evergram_wallet_generate(&wallet) == EVERGRAM_OK &&
        evergram_device_generate(&device) == EVERGRAM_OK) {
        const evergram_options_t options = {
            .url = "wss://gateway.test/ws",
            .wallet = &wallet,
            .device = &device,
            .platform = "Test",
        };
        client = evergram_create(&options);
    }
    evergram_wallet_wipe(&wallet);
    evergram_device_wipe(&device);
    CHECK(client != NULL);
    if (client == NULL) {
        return;
    }

    evergram_widget_t widget;
    evergram_widget_info_t info;
    size_t count = 99;

    CHECK_EQ_INT(evergram_widget_create(NULL, "name", 0, &widget), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_widget_set_enabled(client, NULL, true, 0, &widget),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_widget_set_enabled(client, "", true, 0, &widget),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_widget_set_config(client, "w", NULL, 0), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_widget_delete(client, NULL, 0), EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_widget_get_info(client, NULL, 0, &info), EVERGRAM_ERR_INVALID_ARG);
    /* An array without room, or without an array, is a caller bug. */
    CHECK_EQ_INT(evergram_widget_list(client, 0, NULL, 4, &count), EVERGRAM_ERR_INVALID_ARG);

    /* The count is cleared before anything else can fail. */
    CHECK_EQ_INT((long long)count, 0LL);

    /* Offline, the connection guard fires before any send. */
    CHECK_EQ_INT(evergram_widget_create(client, "name", 0, &widget), EVERGRAM_ERR_NOT_CONNECTED);
    CHECK_EQ_INT(evergram_widget_list(client, 0, &widget, 1, &count), EVERGRAM_ERR_NOT_CONNECTED);
    CHECK_EQ_INT(evergram_widget_get_info(client, "w", 0, &info), EVERGRAM_ERR_NOT_CONNECTED);

    evergram_destroy(client);
}

static const test_case_t TESTS[] = {
    {"widgets: only flagged config fields are sent", test_config_fill_sends_only_flagged_fields},
    {"widgets: a widget record maps across", test_widget_from_proto},
    {"widgets: public widget info maps across", test_widget_info_from_proto},
    {"widgets: argument and buffer validation", test_widget_call_validation},
};

const test_case_t *widget_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
