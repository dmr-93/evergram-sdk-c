#include <string.h>

#include "evergram.h"
#include "evergram.pb-c.h"
#include "internal.h"
#include "test.h"

/*
 * Purchases. This is the one surface with no reference-SDK counterpart (it ships
 * no wrapper for these messages), so what is pinned here is the proto mapping:
 * which fields of an answer become what a caller reads, and the two decisions
 * that are easy to get wrong — an already-open intent from another device wins
 * over a fresh transaction, and a subscription is only active while it has not
 * expired.
 */

static void test_subscription_maps_and_expires(void) {
    Evergram__Subscription subscription = EVERGRAM__SUBSCRIPTION__INIT;
    subscription.type = (char *)"pro";
    subscription.has_issued_at = 1;
    subscription.issued_at = 1700000000000;
    subscription.has_expires_at = 1;
    subscription.expires_at = 1702592000000;
    subscription.has_days_remaining = 1;
    subscription.days_remaining = 30;
    subscription.token_id = (char *)"token-1";

    evergram_subscription_t mapped;
    evergram_subscription_from_proto(&subscription, &mapped);
    CHECK_EQ_STR(mapped.type, "pro");
    CHECK_EQ_INT((long long)mapped.issued_at_ms, 1700000000000LL);
    CHECK_EQ_INT((long long)mapped.expires_at_ms, 1702592000000LL);
    CHECK_EQ_INT(mapped.days_remaining, 30);
    CHECK_EQ_STR(mapped.token_id, "token-1");

    CHECK(evergram_subscription_is_active(&mapped, 1700000000000ULL));
    CHECK(evergram_subscription_is_active(&mapped, 1702591999999ULL));
    /* The expiry instant itself is no longer active. */
    CHECK(!evergram_subscription_is_active(&mapped, 1702592000000ULL));
    CHECK(!evergram_subscription_is_active(&mapped, 1800000000000ULL));

    /* Nothing known is not "active", and neither is a missing pointer. */
    evergram_subscription_t empty;
    memset(&empty, 0, sizeof(empty));
    CHECK(!evergram_subscription_is_active(&empty, 0));
    CHECK(!evergram_subscription_is_active(NULL, 1000));

    evergram_subscription_from_proto(NULL, &mapped);
    CHECK_EQ_STR(mapped.type, "");
    CHECK_EQ_INT((long long)mapped.expires_at_ms, 0LL);
    evergram_subscription_from_proto(&subscription, NULL); /* must not crash */
}

static void test_initiate_maps_a_payment(void) {
    Evergram__PaymentTxn__HookParameterWrapper__HookParameterData hook =
        EVERGRAM__PAYMENT_TXN__HOOK_PARAMETER_WRAPPER__HOOK_PARAMETER_DATA__INIT;
    hook.hookparametername = (char *)"AMOUNT";
    hook.hookparametervalue = (char *)"5000000";

    Evergram__PaymentTxn__HookParameterWrapper hook_wrapper =
        EVERGRAM__PAYMENT_TXN__HOOK_PARAMETER_WRAPPER__INIT;
    hook_wrapper.hookparameter = &hook;
    Evergram__PaymentTxn__HookParameterWrapper *hooks[1] = {&hook_wrapper};

    Evergram__PaymentTxn__MemoWrapper__MemoData memo =
        EVERGRAM__PAYMENT_TXN__MEMO_WRAPPER__MEMO_DATA__INIT;
    memo.memodata = (char *)"intent-1";
    memo.memotype = (char *)"evergram/purchase";
    memo.memoformat = (char *)"text/plain";
    Evergram__PaymentTxn__MemoWrapper memo_wrapper = EVERGRAM__PAYMENT_TXN__MEMO_WRAPPER__INIT;
    memo_wrapper.memo = &memo;
    Evergram__PaymentTxn__MemoWrapper *memos[1] = {&memo_wrapper};

    Evergram__PaymentTxn payment = EVERGRAM__PAYMENT_TXN__INIT;
    payment.transactiontype = (char *)"Payment";
    payment.destination = (char *)"rDestination";
    payment.amount = (char *)"5000000";
    payment.n_hookparameters = 1;
    payment.hookparameters = hooks;
    payment.n_memos = 1;
    payment.memos = memos;

    Evergram__InitiatePurchaseResponse response = EVERGRAM__INITIATE_PURCHASE_RESPONSE__INIT;
    response.intent_id = (char *)"intent-1";
    response.payment = &payment;

    evergram_purchase_t purchase;
    evergram_purchase_from_initiate(&response, &purchase);
    CHECK_EQ_STR(purchase.intent_id, "intent-1");
    CHECK(purchase.has_payment);
    CHECK_EQ_STR(purchase.payment.transaction_type, "Payment");
    CHECK_EQ_STR(purchase.payment.destination, "rDestination");
    CHECK_EQ_STR(purchase.payment.amount, "5000000");
    CHECK_EQ_INT((long long)purchase.payment.hook_param_count, 1LL);
    CHECK_EQ_STR(purchase.payment.hook_params[0].name, "AMOUNT");
    CHECK_EQ_STR(purchase.payment.hook_params[0].value, "5000000");
    CHECK_EQ_INT((long long)purchase.payment.memo_count, 1LL);
    CHECK_EQ_STR(purchase.payment.memos[0].data, "intent-1");
    CHECK_EQ_STR(purchase.payment.memos[0].type, "evergram/purchase");
    CHECK(!purchase.has_subscription);
    CHECK(!purchase.already_subscribed);
    CHECK(!purchase.has_existing_intent);
}

/* Another device's open intent is what should be paid, so its transaction wins
 * over the fresh one the gateway also returned. */
static void test_open_intent_takes_precedence(void) {
    Evergram__PaymentTxn fresh = EVERGRAM__PAYMENT_TXN__INIT;
    fresh.transactiontype = (char *)"Payment";
    fresh.destination = (char *)"rFresh";
    fresh.amount = (char *)"1";

    Evergram__PaymentTxn older = EVERGRAM__PAYMENT_TXN__INIT;
    older.transactiontype = (char *)"Payment";
    older.destination = (char *)"rOlder";
    older.amount = (char *)"2";

    Evergram__ExistingIntent intent = EVERGRAM__EXISTING_INTENT__INIT;
    intent.intent_id = (char *)"intent-old";
    intent.plan = (char *)"pro";
    intent.has_created_at = 1;
    intent.created_at = 1700000000000;
    intent.has_expires_at = 1;
    intent.expires_at = 1700003600000;
    intent.payment = &older;

    Evergram__InitiatePurchaseResponse response = EVERGRAM__INITIATE_PURCHASE_RESPONSE__INIT;
    response.intent_id = (char *)"intent-new";
    response.payment = &fresh;
    response.existing_intent = &intent;

    evergram_purchase_t purchase;
    evergram_purchase_from_initiate(&response, &purchase);
    CHECK(purchase.has_existing_intent);
    CHECK_EQ_STR(purchase.existing_intent.intent_id, "intent-old");
    CHECK_EQ_STR(purchase.existing_intent.plan, "pro");
    CHECK_EQ_INT((long long)purchase.existing_intent.expires_at_ms, 1700003600000LL);
    CHECK(purchase.has_payment);
    CHECK_EQ_STR(purchase.payment.destination, "rOlder"); /* the intent's transaction */
    CHECK_EQ_STR(purchase.payment.amount, "2");
}

static void test_already_subscribed(void) {
    Evergram__AlreadySubscribedInfo info = EVERGRAM__ALREADY_SUBSCRIBED_INFO__INIT;
    info.has_expires_at = 1;
    info.expires_at = 1702592000000;
    info.has_days_remaining = 1;
    info.days_remaining = 12;
    info.token_id = (char *)"token-9";
    info.source = (char *)"manual";

    Evergram__InitiatePurchaseResponse response = EVERGRAM__INITIATE_PURCHASE_RESPONSE__INIT;
    response.already_subscribed = &info;

    evergram_purchase_t purchase;
    evergram_purchase_from_initiate(&response, &purchase);
    CHECK(purchase.already_subscribed);
    CHECK_EQ_INT((long long)purchase.existing_subscription.expires_at_ms, 1702592000000LL);
    CHECK_EQ_INT(purchase.existing_subscription.days_remaining, 12);
    CHECK_EQ_STR(purchase.existing_subscription.token_id, "token-9");
    CHECK_EQ_STR(purchase.existing_source, "manual");
    CHECK(!purchase.has_payment);
    CHECK(!purchase.has_subscription);

    evergram_purchase_from_initiate(NULL, &purchase);
    CHECK_EQ_STR(purchase.intent_id, "");
    evergram_purchase_from_initiate(&response, NULL); /* must not crash */
}

static void test_purchase_call_validation(void) {
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

    evergram_purchase_t purchase;
    evergram_subscription_t subscription;

    CHECK_EQ_INT(evergram_purchase_initiate(NULL, NULL, NULL, NULL, 0, &purchase),
                 EVERGRAM_ERR_INVALID_ARG);
    /* An intent id and a hash are both required to verify. */
    CHECK_EQ_INT(evergram_purchase_verify(client, NULL, "hash", NULL, 0, &subscription),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_purchase_verify(client, "", "hash", NULL, 0, &subscription),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_purchase_verify(client, "intent", NULL, NULL, 0, &subscription),
                 EVERGRAM_ERR_INVALID_ARG);
    CHECK_EQ_INT(evergram_purchase_claim_pro(NULL, NULL, 0, &subscription),
                 EVERGRAM_ERR_INVALID_ARG);

    /* Offline, the connection guard fires before anything is sent, and the
     * caller's output stays empty rather than half-filled. */
    memset(&subscription, 0xff, sizeof(subscription));
    CHECK_EQ_INT(evergram_purchase_verify(client, "intent", "hash", NULL, 0, &subscription),
                 EVERGRAM_ERR_NOT_CONNECTED);
    CHECK_EQ_INT(subscription.type[0], '\0');
    CHECK_EQ_INT(subscription.expires_at_ms == 0, 1);

    CHECK_EQ_INT(evergram_purchase_initiate(client, NULL, NULL, NULL, 0, &purchase),
                 EVERGRAM_ERR_NOT_CONNECTED);
    CHECK_EQ_INT(purchase.intent_id[0], '\0');
    CHECK_EQ_INT(evergram_purchase_claim_pro(client, NULL, 0, &subscription),
                 EVERGRAM_ERR_NOT_CONNECTED);

    evergram_destroy(client);
}

static const test_case_t TESTS[] = {
    {"purchases: a subscription maps and expires", test_subscription_maps_and_expires},
    {"purchases: initiate maps the transaction", test_initiate_maps_a_payment},
    {"purchases: an open intent wins", test_open_intent_takes_precedence},
    {"purchases: already subscribed", test_already_subscribed},
    {"purchases: argument validation", test_purchase_call_validation},
};

const test_case_t *purchase_tests(size_t *count) {
    *count = sizeof(TESTS) / sizeof(TESTS[0]);
    return TESTS;
}
