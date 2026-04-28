#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <fstream>

#include "nlohmann/json.hpp"
#include "pbc.h"
#include "MABE.hpp"   // uses your encrypt(), decrypt(), SplitString(), convertFromString()

using json = nlohmann::json;

struct mabe_ctx {
    pairing_t pairing;
    element_t g1, g2, e_g1g2;
    bool inited;
};

static bool load_pairing(pairing_t pairing, const char* param_path) {
    FILE* fp = fopen(param_path, "rb");
    if (!fp) return false;

    char param[2048];
    size_t count = fread(param, 1, sizeof(param), fp);
    fclose(fp);
    if (!count) return false;

    pairing_init_set_buf(pairing, param, count);
    return true;
}

static bool load_public(mabe_ctx* ctx, const char* public_json_path) {
    std::ifstream jf(public_json_path, std::ios::in);
    if (!jf) return false;
    json publicInfo = json::parse(jf);

    element_init_G1(ctx->g1, ctx->pairing);
    element_init_G2(ctx->g2, ctx->pairing);
    element_init_GT(ctx->e_g1g2, ctx->pairing);

    convertFromString(ctx->g1, publicInfo["g1"]);
    convertFromString(ctx->g2, publicInfo["g2"]);
    convertFromString(ctx->e_g1g2, publicInfo["e_g1g2"]);
    return true;
}

/* Convert 16 bytes big-endian to mpz. */
static void mpz_from_u128_be(mpz_t out, const uint8_t in16[16]) {
    mpz_import(out, 16, 1 /* msw first */, 1 /* size */, 1 /* big endian */, 0, in16);
}

/* Export mpz to fixed 16 bytes big-endian. */
static void mpz_to_u128_be_fixed(mpz_t v, uint8_t out16[16]) {
    memset(out16, 0, 16);
    size_t wrote = 0;
    uint8_t tmp[64];
    memset(tmp, 0, sizeof(tmp));
    mpz_export(tmp, &wrote, 1, 1, 1, 0, v);
    if (wrote >= 16) {
        memcpy(out16, tmp + (wrote - 16), 16);
    } else {
        memcpy(out16 + (16 - wrote), tmp, wrote);
    }
}

/* Parse element_snprint output that looks like "...[a,b]..." and extract a,b as base10 mpz. */
static int parse_pair_from_element_snprint(const char* s, mpz_t a, mpz_t b) {
    std::string str = s;
    auto p1 = SplitString(str, '[');
    if (p1.size() < 2) return -1;
    auto p2 = SplitString(p1[1], ']');
    if (p2.empty()) return -2;
    auto p3 = SplitString(p2[0], ',');
    if (p3.size() < 2) return -3;

    if (mpz_set_str(a, p3[0].c_str(), 10) != 0) return -4;
    if (mpz_set_str(b, p3[1].c_str(), 10) != 0) return -5;
    return 0;
}

extern "C" {

mabe_ctx* mabe_ctx_create(const char* param_path, const char* public_json_path) {
    auto* ctx = new mabe_ctx();
    ctx->inited = false;

    if (!load_pairing(ctx->pairing, param_path)) { delete ctx; return nullptr; }
    if (!load_public(ctx, public_json_path)) { pairing_clear(ctx->pairing); delete ctx; return nullptr; }

    ctx->inited = true;
    return ctx;
}

void mabe_ctx_free(mabe_ctx* ctx) {
    if (!ctx) return;
    if (ctx->inited) {
        element_clear(ctx->g1);
        element_clear(ctx->g2);
        element_clear(ctx->e_g1g2);
        pairing_clear(ctx->pairing);
    }
    delete ctx;
}

int mabe_decrypt_key32_files(mabe_ctx* ctx,
                            const char* encrypt_json_path,
                            const char* user_json_path,
                            uint8_t out_key32[32]) {
    if (!ctx || !ctx->inited || !out_key32) return -1;

    std::ifstream encf(encrypt_json_path, std::ios::in);
    if (!encf) return -2;
    json enc_msg = json::parse(encf);

    std::ifstream userf(user_json_path, std::ios::in);
    if (!userf) return -3;
    json userInfo = json::parse(userf);

    // Same as your MABE-decrypt.cpp
    element_t msg, decrypted_msg;
    element_init_GT(msg, ctx->pairing);
    element_init_GT(decrypted_msg, ctx->pairing);
    element_from_hash(msg, (void*)"Hello", 5);

    decrypt(enc_msg, userInfo, ctx->pairing, ctx->g1, ctx->g2, ctx->e_g1g2, msg, decrypted_msg);

    // Reconstruct key halves from decrypted_msg and D1/D2 (your testing block)
    mpz_t D1, D2;
    mpz_init(D1); mpz_init(D2);

    {
        std::string s = enc_msg["D1"];
        if (mpz_set_str(D1, s.c_str(), 10) != 0) { mpz_clear(D1); mpz_clear(D2); return -4; }
        s = enc_msg["D2"];
        if (mpz_set_str(D2, s.c_str(), 10) != 0) { mpz_clear(D1); mpz_clear(D2); return -5; }
    }

    char buf[512];
    element_snprint(buf, sizeof(buf), decrypted_msg);

    mpz_t side1p, side2p;
    mpz_init(side1p); mpz_init(side2p);

    int prc = parse_pair_from_element_snprint(buf, side1p, side2p);
    if (prc != 0) {
        mpz_clear(D1); mpz_clear(D2);
        mpz_clear(side1p); mpz_clear(side2p);
        return -6;
    }

    // Your code: side = side - D
    mpz_sub(side1p, side1p, D1);
    mpz_sub(side2p, side2p, D2);

    uint8_t k1[16], k2[16];
    mpz_to_u128_be_fixed(side1p, k1);
    mpz_to_u128_be_fixed(side2p, k2);

    memcpy(out_key32, k1, 16);
    memcpy(out_key32 + 16, k2, 16);

    mpz_clear(D1); mpz_clear(D2);
    mpz_clear(side1p); mpz_clear(side2p);

    element_clear(msg);
    element_clear(decrypted_msg);
    return 0;
}

int mabe_encrypt_json_for_key32_files(mabe_ctx* ctx,
                                     const char* auth1_json_path,
                                     const char* auth2_json_path,
                                     const char* auth3_json_path,
                                     const uint8_t key32[32],
                                     char* out_json,
                                     size_t out_json_cap,
                                     size_t* out_json_len) {
    if (!ctx || !ctx->inited || !key32 || !out_json_len) return -1;

    // Load Auth1/2/3.json (exactly like MABE-encrypt.cpp)
    std::ifstream a1f(auth1_json_path, std::ios::in);
    std::ifstream a2f(auth2_json_path, std::ios::in);
    std::ifstream a3f(auth3_json_path, std::ios::in);
    if (!a1f || !a2f || !a3f) return -2;

    json auth1 = json::parse(a1f);
    json auth2 = json::parse(a2f);
    json auth3 = json::parse(a3f);

    json attributes;
    attributes["T_1_1"] = auth1["T_a1"];
    attributes["T_1_2"] = auth1["T_a2"];
    attributes["T_2_1"] = auth2["T_a1"];
    attributes["T_2_3"] = auth2["T_a3"];
    attributes["T_3_2"] = auth3["T_a2"];
    attributes["T_3_3"] = auth3["T_a3"];

    // Build msg as in your encrypt.cpp
    element_t msg;
    element_init_GT(msg, ctx->pairing);
    element_from_hash(msg, (void*)"Hello", 5);

    // Compute D1/D2 deltas exactly like your "Testing" block
    char buf[512];
    element_snprint(buf, sizeof(buf), msg);

    mpz_t D1, D2;
    mpz_init(D1); mpz_init(D2);
    int prc = parse_pair_from_element_snprint(buf, D1, D2);
    if (prc != 0) {
        mpz_clear(D1); mpz_clear(D2);
        element_clear(msg);
        return -3;
    }

    mpz_t side1, side2;
    mpz_init(side1); mpz_init(side2);
    mpz_from_u128_be(side1, key32);          // first 16 bytes
    mpz_from_u128_be(side2, key32 + 16);     // second 16 bytes

    // Your code: Delta = element_component - side
    mpz_sub(D1, D1, side1);
    mpz_sub(D2, D2, side2);

    // Load Y from Auth1 and g2 from ctx
    element_t Y;
    element_init_GT(Y, ctx->pairing);
    convertFromString(Y, auth1["Y_All"]);

    json enc_msg = encrypt(msg, attributes, Y, ctx->g2, ctx->pairing);

    // add D1/D2 as decimal strings like your encrypt.cpp
    {
        char tmp[1024];
        mpz_get_str(tmp, 10, D1);
        enc_msg["D1"] = std::string(tmp);
        mpz_get_str(tmp, 10, D2);
        enc_msg["D2"] = std::string(tmp);
    }

    std::string out = enc_msg.dump();

    // output buffer handling
    *out_json_len = out.size();
    if (!out_json || out_json_cap == 0) {
        mpz_clear(D1); mpz_clear(D2);
        mpz_clear(side1); mpz_clear(side2);
        element_clear(Y);
        element_clear(msg);
        return -28; // ENOSPC style: caller can retry with out_json_len+1
    }
    if (out.size() + 1 > out_json_cap) {
        mpz_clear(D1); mpz_clear(D2);
        mpz_clear(side1); mpz_clear(side2);
        element_clear(Y);
        element_clear(msg);
        return -28;
    }

    memcpy(out_json, out.data(), out.size());
    out_json[out.size()] = '\0';

    mpz_clear(D1); mpz_clear(D2);
    mpz_clear(side1); mpz_clear(side2);
    element_clear(Y);
    element_clear(msg);
    return 0;
}

} // extern "C"