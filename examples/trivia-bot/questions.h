/*
 * Trivia questions, generated from the TypeScript SDK's questions.ts so both
 * bots ask exactly the same rounds.
 */
#ifndef EVERGRAM_TRIVIA_QUESTIONS_H
#define EVERGRAM_TRIVIA_QUESTIONS_H

typedef struct {
    const char *question;
    const char *answer;
} trivia_question_t;

static const trivia_question_t TRIVIA_QUESTIONS[] = {
    {"What consensus algorithm does the XRP Ledger use?", "XRPL Consensus Protocol"},
    {"What is the native token of the Xahau Network called?", "XAH"},
    {"What do you call a host machine that leases compute to Evernode instances?", "host"},
    {"What smart contract technology does Xahau add on top of the XRPL codebase?", "Hooks"},
    {"What is Evergram's smart contract layer built on, running as an Evernode instance?", "HotPocket"},
    {"What XRPL primitive lets an issuer freeze or restrict a token?", "trust line"},
    {"What is the unit of currency leased for hosting on Evernode called?", "EVR"},
    {"What language are XRPL Hooks written in before compiling to WebAssembly?", "C"},
    {"What consensus algorithm family does the XRPL Consensus Protocol belong to?", "Federated Byzantine Agreement"},
    {"Which XLS standard defines NFTs on the XRP Ledger?", "XLS-20"},
    {"What XRPL feature lets you lock XRP until a time or condition is met?", "Escrow"},
    {"What software do Evernode hosts run to manage their leased instances?", "Sashimono"},
    {"What do you call the time unit Evernode uses to measure a lease's duration?", "moment"},
    {"What type of token represents an Evernode host registration or lease?", "URIToken"},
    {"What do XRPL Hooks compile down to before running on Xahau?", "WebAssembly"},
    {"What is the XRP Ledger's built-in decentralized exchange feature called?", "DEX"},
    {"What is the ticker symbol for the XRP Ledger's native asset?", "XRP"},
    {"What do you call an XRPL account that issues a non-XRP currency?", "issuer"},
    {"What happens to the XRP paid as XRPL network transaction fees?", "burned"},
    {"What XRPL feature enables high-throughput, off-ledger streaming payments settled on-chain?", "Payment Channels"},
    {"What XRPL object type represents a deferred, cashable payment authorization?", "Check"},
    {"What XRPL feature lets an account require multiple keys to authorize a transaction?", "Multi-signing"},
    {"What is the name for a candidate protocol upgrade that XRPL validators vote to activate?", "Amendment"},
    {"What is the reference server implementation of the XRP Ledger protocol called?", "rippled"},
    {"What is the name of the native liquidity-pool feature added to the XRPL via amendment?", "AMM"},
    {"What XRPL amendment lets an issuer reclaim tokens it issued from a holder's account?", "Clawback"},
    {"In XRPL terms, what is the minimum XRP balance an account must hold called?", "reserve"},
    {"What protocol do XRPL clients typically use to submit transactions and subscribe to ledger updates in real time?", "WebSocket"},
    {"What optional numeric field lets one XRPL account distinguish payments meant for different sub-accounts, e.g. on an exchange?", "Destination Tag"},
    {"What year did the XRP Ledger go live?", "2012"},
    {"What company originally created the XRP Ledger?", "Ripple"},
    {"What is the reference node software for the Xahau Network called?", "xahaud"},
};

#define TRIVIA_QUESTION_COUNT (sizeof(TRIVIA_QUESTIONS) / sizeof(TRIVIA_QUESTIONS[0]))

#endif /* EVERGRAM_TRIVIA_QUESTIONS_H */
