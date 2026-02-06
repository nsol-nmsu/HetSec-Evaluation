/*
 * Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <vector>
#include <string>
#include <assert.h>
#include <fstream>
#ifndef QVL_ONLY
#include <sgx_uae_launch.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#else
#include <cstring>
#endif
#include "sgx_ql_quote.h"
#include "sgx_dcap_quoteverify.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <iostream>
#include <fcntl.h>


#if SGX_QPL_LOGGING
#include "sgx_default_quote_provider.h"
#ifdef _MSC_VER
typedef quote3_error_t(*sgx_ql_set_logging_callback_t)(sgx_ql_logging_callback_t, sgx_ql_log_level_t);
#endif
#endif

#ifndef _MSC_VER

#define SAMPLE_ISV_ENCLAVE "enclave.signed.so"
#define DEFAULT_QUOTE "../QuoteGenerationSample/quote.dat"

#else

#define SAMPLE_ISV_ENCLAVE "enclave.signed.dll"
#define DEFAULT_QUOTE "..\\..\\..\\QuoteGenerationSample\\x64\\Debug\\quote.dat"
#define QPL_LIB_NAME "dcap_quoteprov.dll"
#define strncpy strncpy_s
#endif
#ifndef SGX_CDECL
#define SGX_CDECL
#endif




using namespace std;
#define log(msg, ...)                             \
    do                                            \
    {                                             \
        printf("[APP] " msg "\n", ##__VA_ARGS__); \
        fflush(stdout);                           \
    } while (0)

typedef union _supp_ver_t
{
    uint32_t version;
    struct
    {
        uint16_t major_version;
        uint16_t minor_version;
    };
} supp_ver_t;


#ifndef QVL_ONLY
static sgx_enclave_id_t g_eid = 0;
static int g_enclave_updated = 0;
static sgx_launch_token_t g_token = {0};
static sgx_ql_qe_report_info_t g_qve_template;
static bool g_qve_ready = false;

static bool fill_nonce_16(unsigned char out[16]) {
    int fd = ::open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    ssize_t r = ::read(fd, out, 16);
    ::close(fd);
    return r == 16;
}

static int init_qve_context() {
    if (g_qve_ready) return 0;

    memset(&g_qve_template, 0, sizeof(g_qve_template));

    sgx_status_t sgx_ret = sgx_create_enclave(
        SAMPLE_ISV_ENCLAVE, SGX_DEBUG_FLAG, &g_token, &g_enclave_updated, &g_eid, NULL
    );
    if (sgx_ret != SGX_SUCCESS) {
        log("Error: Can't load SampleISVEnclave. 0x%04x", sgx_ret);
        return -1;
    }

    sgx_status_t get_target_info_ret = SGX_SUCCESS;
    sgx_ret = ecall_get_target_info(g_eid, &get_target_info_ret, &g_qve_template.app_enclave_target_info);
    if (sgx_ret != SGX_SUCCESS || get_target_info_ret != SGX_SUCCESS) {
        log("Error: ecall_get_target_info failed. 0x%04x", get_target_info_ret);
        sgx_destroy_enclave(g_eid);
        g_eid = 0;
        return -1;
    }

    quote3_error_t dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
    if (dcap_ret != TEE_SUCCESS) {
        log("Error: sgx_qv_set_enclave_load_policy failed: 0x%04x", dcap_ret);
        sgx_destroy_enclave(g_eid);
        g_eid = 0;
        return -1;
    }

    g_qve_ready = true;
    return 0;
}

static void shutdown_qve_context() {
    if (g_eid) {
        sgx_destroy_enclave(g_eid);
        g_eid = 0;
    }
    g_qve_ready = false;
}
#endif



vector<uint8_t> readBinaryContent(const string &filePath)
{
    ifstream file(filePath, ios::binary);
    if (!file.is_open())
    {
        log("Error: Unable to open quote file %s", filePath.c_str());
        return {};
    }

    file.seekg(0, ios_base::end);
    streampos fileSize = file.tellg();

    file.seekg(0, ios_base::beg);
    vector<uint8_t> retVal(fileSize);
    file.read(reinterpret_cast<char *>(retVal.data()), fileSize);
    file.close();
    return retVal;
}
#define PATHSIZE 0x418U

/**
 * @param quote - ECDSA quote buffer
 * @param use_qve - Set quote verification mode
 *                   If true, quote verification will be performed by Intel QvE
 *                   If false, quote verification will be performed by untrusted QVL
 */

int ecdsa_quote_verification(vector<uint8_t> quote, bool use_qve)
{
#ifndef QVL_ONLY
    sgx_status_t sgx_ret = SGX_SUCCESS;
    sgx_ql_qe_report_info_t qve_report_info;
    int updated = 0;
    sgx_launch_token_t token = {0};
    unsigned char rand_nonce[16] = "59jslk201fgjmm;";
    quote3_error_t verify_qveid_ret = TEE_ERROR_UNEXPECTED;
    sgx_enclave_id_t eid = 0;
#else
    (void)use_qve;
#endif

    int ret = 0;
    time_t current_time = 0;
    quote3_error_t dcap_ret = TEE_ERROR_UNEXPECTED;
    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = TEE_QV_RESULT_UNSPECIFIED;
    

    tee_supp_data_descriptor_t supp_data;

    // You can also set specify a major version in this structure, then we will always return supplemental data of the major version
    // set major verison to 0 means always return latest supplemental data
    memset(&supp_data, 0, sizeof(tee_supp_data_descriptor_t));

    supp_ver_t latest_ver;

 #ifndef QVL_ONLY
    // Trusted quote verification
    if (use_qve)
    {
        // set nonce
        //
        memcpy(qve_report_info.nonce.rand, rand_nonce, sizeof(rand_nonce));

        // get target info of SampleISVEnclave. QvE will target the generated report to this enclave.
        //
        sgx_ret = sgx_create_enclave(SAMPLE_ISV_ENCLAVE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
        if (sgx_ret != SGX_SUCCESS)
        {
            log("Error: Can't load SampleISVEnclave. 0x%04x", sgx_ret);
            return -1;
        }
        sgx_status_t get_target_info_ret;
        sgx_ret = ecall_get_target_info(eid, &get_target_info_ret, &qve_report_info.app_enclave_target_info);
        if (sgx_ret != SGX_SUCCESS || get_target_info_ret != SGX_SUCCESS)
        {
            log("Error in sgx_get_target_info. 0x%04x", get_target_info_ret);
            ret = -1;
            goto cleanup;
        }
        else
        {
            log("Info: get target info successfully returned.");
        }

        // call DCAP quote verify library to set QvE loading policy
        //
        dcap_ret = sgx_qv_set_enclave_load_policy(SGX_QL_DEFAULT);
        if (dcap_ret == TEE_SUCCESS)
        {
            log("Info: sgx_qv_set_enclave_load_policy successfully returned.");
        }
        else
        {
            log("Error: sgx_qv_set_enclave_load_policy failed: 0x%04x", dcap_ret);
            ret = -1;
            goto cleanup;
        }

        // call DCAP quote verify library to get supplemental latest version and data size
        // version is a combination of major_version and minor version
        // you can set the major version in 'supp_data.major_version' to get old version supplemental data
        // only support major_version 3 right now
        dcap_ret = tee_get_supplemental_data_version_and_size(quote.data(),
                                                              (uint32_t)quote.size(),
                                                              &latest_ver.version,
                                                              &supp_data.data_size);

        if (dcap_ret == TEE_SUCCESS && supp_data.data_size == sizeof(sgx_ql_qv_supplemental_t))
        {
            log("Info: tee_get_quote_supplemental_data_version_and_size successfully returned.");
            log("Info: latest supplemental data major version: %d, minor version: %d, size: %d", latest_ver.major_version, latest_ver.minor_version, supp_data.data_size);
            supp_data.p_data = (uint8_t *)malloc(supp_data.data_size);
            if (supp_data.p_data != NULL)
            {
                memset(supp_data.p_data, 0, supp_data.data_size);
            }

            // Just print error in sample
            //
            else
            {
                log("Error: Cannot allocate memory for supplemental data.");
                supp_data.data_size = 0;
            }
        }
        else
        {
            if (dcap_ret != TEE_SUCCESS)
                log("Error: tee_get_quote_supplemental_data_size failed: 0x%04x", dcap_ret);

            if (supp_data.data_size != sizeof(sgx_ql_qv_supplemental_t))
                log("Warning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.");

            supp_data.data_size = 0;
        }

        // set current time. This is only for sample use, please use trusted time in product.
        //
        current_time = time(NULL);

        // call DCAP quote verify library for quote verification
        // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
        // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
        // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
        dcap_ret = tee_verify_quote(
            quote.data(), (uint32_t)quote.size(),
            NULL,
            current_time,
            &collateral_expiration_status,
            &quote_verification_result,
            &qve_report_info,
            &supp_data);
        if (dcap_ret == TEE_SUCCESS)
        {
            log("Info: App: tee_verify_quote successfully returned.");
        }
        else
        {
            log("Error: App: tee_verify_quote failed: 0x%04x", dcap_ret);
            ret = -1;
            goto cleanup;
        }

        // Threshold of QvE ISV SVN. The ISV SVN of QvE used to verify quote must be greater or equal to this threshold
        // e.g. You can check latest QvE ISVSVN from QvE configuration file on Github
        // https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/QvE/Enclave/linux/config.xml#L4
        // or you can get latest QvE ISVSVN in QvE Identity JSON file from
        // https://api.trustedservices.intel.com/sgx/certification/v4/qve/identity
        // Make sure you are using trusted & latest QvE ISV SVN as threshold
        // Warning: The function may return erroneous result if QvE ISV SVN has been modified maliciously.
        //
        sgx_isv_svn_t qve_isvsvn_threshold = 7;

        // call sgx_dcap_tvl API in SampleISVEnclave to verify QvE's report and identity
        //
        sgx_ret = sgx_tvl_verify_qve_report_and_identity(eid,
                                                         &verify_qveid_ret,
                                                         quote.data(),
                                                         (uint32_t)quote.size(),
                                                         &qve_report_info,
                                                         current_time,
                                                         collateral_expiration_status,
                                                         quote_verification_result,
                                                         supp_data.p_data,
                                                         supp_data.data_size,
                                                         qve_isvsvn_threshold);

        if (sgx_ret != SGX_SUCCESS || verify_qveid_ret != TEE_SUCCESS)
        {
            log("Error: Ecall: Verify QvE report and identity failed. 0x%04x", verify_qveid_ret);
            ret = -1;
            goto cleanup;
        }
        else
        {
            log("Info: Ecall: Verify QvE report and identity successfully returned.");
        }

        // check verification result
        //
        switch (quote_verification_result)
        {
        case TEE_QV_RESULT_OK:
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            //
            if (collateral_expiration_status == 0)
            {
                log("Info: App: Verification completed successfully.");
                ret = 0;
            }
            else
            {
                log("Warning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
                ret = 1;
            }

            break;
        case TEE_QV_RESULT_CONFIG_NEEDED:
        case TEE_QV_RESULT_OUT_OF_DATE:
        case TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case TEE_QV_RESULT_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
            log("Warning: App: Verification completed with Non-terminal result: %x", quote_verification_result);
            ret = 1;
            break;
        case TEE_QV_RESULT_INVALID_SIGNATURE:
        case TEE_QV_RESULT_REVOKED:
        case TEE_QV_RESULT_UNSPECIFIED:
        default:
            log("Error: App: Verification completed with Terminal result: %x", quote_verification_result);
            ret = -1;
            break;
        }

        // check supplemental data if necessary
        //
        if (dcap_ret == TEE_SUCCESS && supp_data.p_data != NULL && supp_data.data_size > 0)
        {
            sgx_ql_qv_supplemental_t *p = (sgx_ql_qv_supplemental_t *)supp_data.p_data;

            // you can check supplemental data based on your own attestation/verification policy
            // here we only print supplemental data version for demo usage
            //
            log("Info: Supplemental data Major Version: %d", p->major_version);
            log("Info: Supplemental data Minor Version: %d", p->minor_version);

            // print SA list if exist, SA list is supported from version 3.1
            //
            if (p->version > 3 && strlen(p->sa_list) > 0)
            {
                log("Info: Advisory ID: %s", p->sa_list);
            }
        }
    }
    // Untrusted quote verification
    else
#endif
    {
        // call DCAP quote verify library to get supplemental latest version and data size
        // version is a combination of major_version and minor version
        // you can set the major version in 'supp_data.major_version' to get old version supplemental data
        // only support major_version 3 right now
        dcap_ret = tee_get_supplemental_data_version_and_size(quote.data(),
                                                              (uint32_t)quote.size(),
                                                              &latest_ver.version,
                                                              &supp_data.data_size);

        if (dcap_ret == TEE_SUCCESS && supp_data.data_size == sizeof(sgx_ql_qv_supplemental_t))
        {
            log("Info: tee_get_quote_supplemental_data_version_and_size successfully returned.");
            log("Info: latest supplemental data major version: %d, minor version: %d, size: %d", latest_ver.major_version, latest_ver.minor_version, supp_data.data_size);
            supp_data.p_data = (uint8_t *)malloc(supp_data.data_size);
            if (supp_data.p_data != NULL)
            {
                memset(supp_data.p_data, 0, supp_data.data_size);
            }

            // Just print error in sample
            //
            else
            {
                log("Error: Cannot allocate memory for supplemental data.");
                supp_data.data_size = 0;
            }
        }
        else
        {
            if (dcap_ret != TEE_SUCCESS)
                log("Error: tee_get_quote_supplemental_data_size failed: 0x%04x", dcap_ret);

            if (supp_data.data_size != sizeof(sgx_ql_qv_supplemental_t))
                log("Warning: Quote supplemental data size is different between DCAP QVL and QvE, please make sure you installed DCAP QVL and QvE from same release.");

            supp_data.data_size = 0;
        }

        // set current time. This is only for sample purposes, in production mode a trusted time should be used.
        //
        current_time = time(NULL);

        // call DCAP quote verify library for quote verification
        // here you can choose 'trusted' or 'untrusted' quote verification by specifying parameter '&qve_report_info'
        // if '&qve_report_info' is NOT NULL, this API will call Intel QvE to verify quote
        // if '&qve_report_info' is NULL, this API will call 'untrusted quote verify lib' to verify quote, this mode doesn't rely on SGX capable system, but the results can not be cryptographically authenticated
        dcap_ret = tee_verify_quote(
            quote.data(), (uint32_t)quote.size(),
            NULL,
            current_time,
            &collateral_expiration_status,
            &quote_verification_result,
            NULL,
            &supp_data);
        if (dcap_ret == TEE_SUCCESS)
        {
            log("Info: App: tee_verify_quote successfully returned.");
        }
        else
        {
            log("Error: App: tee_verify_quote failed: 0x%04x", dcap_ret);
            goto cleanup;
        }

        // check verification result
        //
        switch (quote_verification_result)
        {
        case TEE_QV_RESULT_OK:
            // check verification collateral expiration status
            // this value should be considered in your own attestation/verification policy
            //
            if (collateral_expiration_status == 0)
            {
                log("Info: App: Verification completed successfully.");
                ret = 0;
            }
            else
            {
                log("Warning: App: Verification completed, but collateral is out of date based on 'expiration_check_date' you provided.");
                ret = 1;
            }
            break;
        case TEE_QV_RESULT_CONFIG_NEEDED:
        case TEE_QV_RESULT_OUT_OF_DATE:
        case TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case TEE_QV_RESULT_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
            log("Warning: App: Verification completed with Non-terminal result: %x", quote_verification_result);
            ret = 1;
            break;
        case TEE_QV_RESULT_INVALID_SIGNATURE:
        case TEE_QV_RESULT_REVOKED:
        case TEE_QV_RESULT_UNSPECIFIED:
        default:
            log("Error: App: Verification completed with Terminal result: %x", quote_verification_result);
            ret = -1;
            break;
        }

        // check supplemental data if necessary
        //
        if (dcap_ret == TEE_SUCCESS && supp_data.p_data != NULL && supp_data.data_size > 0)
        {
            sgx_ql_qv_supplemental_t *p = (sgx_ql_qv_supplemental_t *)supp_data.p_data;

            // you can check supplemental data based on your own attestation/verification policy
            // here we only print supplemental data version for demo usage
            //
            log("Info: Supplemental data Major Version: %d", p->major_version);
            log("Info: Supplemental data Minor Version: %d", p->minor_version);

            // print SA list if exist, SA list is supported from version 3.1
            //
            if (p->version > 3 && strlen(p->sa_list) > 0)
            {
                log("Info: Advisory ID: %s", p->sa_list);
            }
        }
    }

cleanup:
    if (supp_data.p_data != NULL)
    {
        free(supp_data.p_data);
    }

#ifndef QVL_ONLY
    if (eid)
    {
        sgx_destroy_enclave(eid);
    }
#endif

    return ret;
}

void usage()
{
    log("Usage:");
    log("\tPlease specify quote path, e.g. \"./app -quote <path/to/quote>\"");
    log("\t\tDefault quote path is %s when no command line args", DEFAULT_QUOTE);
}

#if SGX_QPL_LOGGING
void qpl_logger(sgx_ql_log_level_t level, const char *message)
{
    const string pre_qcnl = "[QCNL]";
    const string pre_qpl = "[QPL]";
    string msg(message);
    if (level == SGX_QL_LOG_INFO)
    {
        if (msg.find(pre_qcnl) == 0)
            msg.insert(pre_qcnl.length(), " Info: ");
        else if (msg.find(pre_qpl) == 0)
            msg.insert(pre_qcnl.length(), "Info: ");
        printf("%s", msg.c_str());
    }
    else if (level == SGX_QL_LOG_ERROR)
    {
        if (msg.find(pre_qcnl) == 0)
            msg.insert(pre_qcnl.length(), " Error: ");
        else if (msg.find(pre_qpl) == 0)
            msg.insert(pre_qcnl.length(), "Error: ");
        printf("%s", msg.c_str());
    }
}
#endif



static bool read_exact(int fd, void* buf, size_t n) {
    uint8_t* p = (uint8_t*)buf;
    while (n) {
        ssize_t r = ::read(fd, p, n);
        if (r <= 0) return false;
        p += (size_t)r;
        n -= (size_t)r;
    }
    return true;
}

static bool write_exact(int fd, const void* buf, size_t n) {
    const uint8_t* p = (const uint8_t*)buf;
    while (n) {
        ssize_t w = ::write(fd, p, n);
        if (w <= 0) return false;
        p += (size_t)w;
        n -= (size_t)w;
    }
    return true;
}

// You will implement this by refactoring the existing QuoteVerificationSample logic
// that currently verifies the quote read from a file.
// Return 0 on success. On failure return nonzero and fill out_json with details.
static int VerifyQuoteBytes_QvE(const uint8_t* quote, uint32_t quote_size, std::string& out_json){
    #ifdef QVL_ONLY
    (void)quote; (void)quote_size;
    out_json = "{\"error\":\"built_with_QVL_ONLY\"}";
    return -1;
#else
    if (!quote || quote_size == 0) {
        out_json = "{\"error\":\"empty_quote\"}";
        return -1;
    }
    if (init_qve_context() != 0) {
        out_json = "{\"error\":\"init_qve_context_failed\"}";
        return -1;
    }

    int ret = -1;
    quote3_error_t dcap_ret = TEE_ERROR_UNEXPECTED;
    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = TEE_QV_RESULT_UNSPECIFIED;

    tee_supp_data_descriptor_t supp_data;
    memset(&supp_data, 0, sizeof(supp_data));

    supp_ver_t latest_ver;
    latest_ver.version = 0;

    sgx_isv_svn_t qve_isvsvn_threshold = 7;

    quote3_error_t verify_qveid_ret = TEE_ERROR_UNEXPECTED;
    sgx_status_t sgx_ret = SGX_SUCCESS;

    // Copy cached target info, set fresh nonce for this request
    sgx_ql_qe_report_info_t qve_report_info = g_qve_template;
    unsigned char nonce[16];
    if (!fill_nonce_16(nonce)) {
        out_json = "{\"error\":\"nonce_failed\"}";
        return -1;
    }
    memcpy(qve_report_info.nonce.rand, nonce, 16);

    // supplemental size
    dcap_ret = tee_get_supplemental_data_version_and_size(
        quote, quote_size, &latest_ver.version, &supp_data.data_size
    );

    if (dcap_ret == TEE_SUCCESS && supp_data.data_size == sizeof(sgx_ql_qv_supplemental_t)) {
        supp_data.p_data = (uint8_t*)malloc(supp_data.data_size);
        if (supp_data.p_data) memset(supp_data.p_data, 0, supp_data.data_size);
        else supp_data.data_size = 0;
    } else {
        supp_data.data_size = 0;
        supp_data.p_data = NULL;
    }

    time_t current_time = time(NULL);

    // QvE path: pass non-null qve_report_info
    dcap_ret = tee_verify_quote(
        quote, quote_size,
        NULL,
        current_time,
        &collateral_expiration_status,
        &quote_verification_result,
        &qve_report_info,
        &supp_data
    );

    if (dcap_ret != TEE_SUCCESS) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "{\"dcap_ret\":\"0x%04x\",\"error\":\"tee_verify_quote_failed\"}", dcap_ret);
        out_json = buf;
        ret = -1;
        goto done;
    }

    // Verify QvE report and identity inside SampleISVEnclave
    // Set your own threshold if you want; keep sample value for now.
    
    sgx_ret = sgx_tvl_verify_qve_report_and_identity(
        g_eid,
        &verify_qveid_ret,
        quote, quote_size,
        &qve_report_info,
        current_time,
        collateral_expiration_status,
        quote_verification_result,
        supp_data.p_data,
        supp_data.data_size,
        qve_isvsvn_threshold
    );

    if (sgx_ret != SGX_SUCCESS || verify_qveid_ret != TEE_SUCCESS) {
        char buf[256];
        snprintf(buf, sizeof(buf),
                 "{\"sgx_ret\":\"0x%04x\",\"verify_qveid_ret\":\"0x%04x\",\"error\":\"qve_report_identity_verify_failed\"}",
                 sgx_ret, verify_qveid_ret);
        out_json = buf;
        ret = -1;
        goto done;
    }

    // Map result to rc: 0 ok, 1 nonterminal, -1 terminal
    switch (quote_verification_result) {
        case TEE_QV_RESULT_OK:
            ret = (collateral_expiration_status == 0) ? 0 : 1;
            break;

        case TEE_QV_RESULT_CONFIG_NEEDED:
        case TEE_QV_RESULT_OUT_OF_DATE:
        case TEE_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case TEE_QV_RESULT_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED:
        case TEE_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
            ret = 1;
            break;

        default:
            ret = -1;
            break;
    }

    {
        char buf[512];
        snprintf(buf, sizeof(buf),
            "{\"rc\":%d,\"qv_result\":\"0x%08x\",\"collateral_expired\":%u,"
            "\"supp_major\":%u,\"supp_minor\":%u}",
            ret,
            (unsigned)quote_verification_result,
            (unsigned)collateral_expiration_status,
            (supp_data.p_data && supp_data.data_size >= sizeof(sgx_ql_qv_supplemental_t))
                ? ((sgx_ql_qv_supplemental_t*)supp_data.p_data)->major_version : 0,
            (supp_data.p_data && supp_data.data_size >= sizeof(sgx_ql_qv_supplemental_t))
                ? ((sgx_ql_qv_supplemental_t*)supp_data.p_data)->minor_version : 0
        );
        out_json = buf;
    }

done:
    if (supp_data.p_data) free(supp_data.p_data);
    return ret;
#endif
}


static int run_unix_socket_server(const char* sock_path) {
    ::unlink(sock_path);

    int s = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        std::cerr << "socket() failed: " << strerror(errno) << "\n";
        return 1;
    }

    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    std::snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", sock_path);

    if (::bind(s, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "bind() failed: " << strerror(errno) << "\n";
        ::close(s);
        return 1;
    }

    if (::listen(s, 64) < 0) {
        std::cerr << "listen() failed: " << strerror(errno) << "\n";
        ::close(s);
        return 1;
    }

    std::cerr << "QvE verifier listening on " << sock_path << "\n";

    for (;;) {
        int c = ::accept(s, nullptr, nullptr);
        if (c < 0) continue;

        uint32_t be_len = 0;
        if (!read_exact(c, &be_len, sizeof(be_len))) { ::close(c); continue; }
        uint32_t quote_len = ntohl(be_len);

        if (quote_len == 0 || quote_len > (1024u * 1024u)) { // 1 MB cap
            ::close(c);
            continue;
        }

        std::vector<uint8_t> quote(quote_len);
        if (!read_exact(c, quote.data(), quote.size())) { ::close(c); continue; }

        std::string json;
        int rc = VerifyQuoteBytes_QvE(quote.data(), (uint32_t)quote.size(), json);

        // Response: [u32 rc][u32 json_len][json bytes]
        uint32_t be_rc = htonl((uint32_t)rc);
        uint32_t be_jlen = htonl((uint32_t)json.size());
        if (!write_exact(c, &be_rc, sizeof(be_rc))) { ::close(c); continue; }
        if (!write_exact(c, &be_jlen, sizeof(be_jlen))) { ::close(c); continue; }
        if (!json.empty()) write_exact(c, json.data(), json.size());

        ::close(c);
    }
}


static bool is_nonterminal(sgx_ql_qv_result_t r) {
    switch (r) {
        case SGX_QL_QV_RESULT_OK:
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:          // 0xA002
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED:
        case SGX_QL_QV_RESULT_TD_RELAUNCH_ADVISED_CONFIG_NEEDED:
            return true;
        default:
            return false; // invalid signature, revoked, unspecified, etc.
    }
}

int VerifyQuoteBytes_QVL(const uint8_t* quote, uint32_t quote_size, std::string& out_json) {
    time_t now = time(nullptr);

    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t qv_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    // Optional supplemental data
    uint32_t supp_data_size = 0;
    sgx_qv_get_quote_supplemental_data_size(&supp_data_size);
    std::vector<uint8_t> supp(supp_data_size);

    // If you want the library to fetch collateral automatically, pass nullptr for collateral.
    // If you have your own collateral retrieval, pass it here.
    const sgx_ql_qve_collateral_t* p_collateral = nullptr;

    quote3_error_t ret = sgx_qv_verify_quote(
        quote,
        quote_size,
        p_collateral,
        now,
        &collateral_expiration_status,
        &qv_result,
        nullptr,              // qve_report_info: nullptr means "QVL only"
        supp_data_size,
        supp.data()
    );

    // Define ok: DCAP call success AND qv_result indicates OK.
    bool ok = (ret == SGX_QL_SUCCESS) && is_nonterminal(qv_result);

    // Keep JSON minimal; expand as needed.
    out_json = std::string("{") +
        "\"ok\":" + (ok ? "true" : "false") + "," +
        "\"dcap_ret\":" + std::to_string((uint32_t)ret) + "," +
        "\"qv_result\":" + std::to_string((uint32_t)qv_result) + "," +
        "\"collateral_expiration_status\":" + std::to_string(collateral_expiration_status) +
    "}";

    return (int)ret;
}

static int run_tcp_server(const char* ip, uint16_t port) {
    int s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        std::cerr << "socket() failed: " << strerror(errno) << "\n";
        return 1;
    }

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(s, IPPROTO_TCP, O_NDELAY, &one, sizeof(one));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr(ip); // e.g. "127.0.0.1"

    if (::bind(s, (sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "bind() failed: " << strerror(errno) << "\n";
        ::close(s);
        return 1;
    }

    if (::listen(s, 64) < 0) {
        std::cerr << "listen() failed: " << strerror(errno) << "\n";
        ::close(s);
        return 1;
    }

    std::cerr << "QvE verifier listening on " << ip << ":" << port << "\n";

    for (;;) {
        int c = ::accept(s, nullptr, nullptr);
        if (c < 0) continue;

        // protocol: [u32 len_be][quote bytes] -> [u32 rc_be][u32 json_len_be][json bytes]
        uint32_t be_len = 0;
        if (!read_exact(c, &be_len, sizeof(be_len))) { ::close(c); continue; }
        uint32_t quote_len = ntohl(be_len);

        if (quote_len == 0 || quote_len > (1024u * 1024u)) {
            ::close(c);
            continue;
        }

        std::vector<uint8_t> quote(quote_len);
        if (!read_exact(c, quote.data(), quote.size())) { ::close(c); continue; }

        // Quote verification with QVL
        log("Quote verification with QVL, support both SGX and TDX quote:");
        std::string json;

    #ifdef QVL_ONLY
        int rc = VerifyQuoteBytes_QVL(quote.data(), (uint32_t)quote.size(), json);
    #else

        int rc = VerifyQuoteBytes_QvE(quote.data(), (uint32_t)quote.size(), json);
    #endif        

        uint32_t be_rc = htonl((uint32_t)rc);
        uint32_t be_jlen = htonl((uint32_t)json.size());

        if (!write_exact(c, &be_rc, sizeof(be_rc))) { ::close(c); continue; }
        if (!write_exact(c, &be_jlen, sizeof(be_jlen))) { ::close(c); continue; }
        if (!json.empty()) write_exact(c, json.data(), json.size());

        ::close(c);
    }
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{


    // TCP mode: ./app --tcp 127.0.0.1 7777
    log("\tI out here %d %s", argc, argv[1]);

    if (argc == 4 && std::string(argv[1]) == "--tcp") {
    log("\tI in here");

#ifndef QVL_ONLY
        if (init_qve_context() != 0) return 1;
#endif
        const char* ip = argv[2];
        uint16_t port = (uint16_t)atoi(argv[3]);
        return run_tcp_server(ip, port);
    }

    if (argc >= 3 && std::string(argv[1]) == "--sock") {
    #ifndef QVL_ONLY
        if (init_qve_context() != 0) return 1;
    #endif
        return run_unix_socket_server(argv[2]);
    }
    int ret = 0;
    vector<uint8_t> quote;
#if defined(_MSC_VER)
    HINSTANCE qpl_library_handle = NULL;
#endif

    char quote_path[PATHSIZE] = {'\0'};

    // Just for sample use, better to change solid command line args solution in production env
    if (argc != 1 && argc != 3)
    {
        usage();
        return 0;
    }

    if (argv[1] && argv[2])
    {
        if (!strcmp(argv[1], "-quote"))
        {
            strncpy(quote_path, argv[2], PATHSIZE - 1);
        }
    }

    if (*quote_path == '\0')
    {
        strncpy(quote_path, DEFAULT_QUOTE, PATHSIZE - 1);
    }

    // read quote from file
    //
    quote = readBinaryContent(quote_path);
    if (quote.empty())
    {
        usage();
        return -1;
    }

#if SGX_QPL_LOGGING
#if defined(_MSC_VER)
    qpl_library_handle = LoadLibrary(TEXT(QPL_LIB_NAME));
    if (qpl_library_handle != NULL) {
        sgx_ql_set_logging_callback_t p_sgx_ql_set_logging_callback = (sgx_ql_set_logging_callback_t)GetProcAddress(qpl_library_handle, "sgx_ql_set_logging_callback");
        if (NULL != p_sgx_ql_set_logging_callback) {
            p_sgx_ql_set_logging_callback(qpl_logger, static_cast<sgx_ql_log_level_t>(SGX_QPL_LOGGING - 1));
        }
        else {
            log("Warning: Failed to get address of sgx_ql_set_logging_callback: %lu\n", GetLastError());
        }
    }
    else {
        log("Warning: Your system does not have dcap_quoteprov.dll or sgx_default_qcnl_wrapper.dll: %lu\n", GetLastError());
    }
#else
    sgx_ql_set_logging_callback(qpl_logger, static_cast<sgx_ql_log_level_t>(SGX_QPL_LOGGING - 1));
#endif   
#endif

    log("Info: ECDSA quote path: %s", quote_path);

    // When building with QVL_ONLY = 0 (default), two different types of quote verification are demonstrated
    //    a. Trusted quote verification - quote is verified with Intel QvE
    //    b. Untrusted quote verification - quote is verified with Intel QVL (Quote Verification Library)
    //       This mode does not rely on an SGX/TDX capable system, but the results cannot be cryptographically authenticated
    // If built with QVL_ONLY = 1, only one type of quote verification will be demonstrated
    //    a. Untrusted quote verification - quote is verified with Intel QVL (Quote Verification Library)
    //       This mode does not rely on an SGX/TDX capable system, but the results cannot be cryptographically authenticated

#ifndef QVL_ONLY
    // Trusted quote verification, ignore error checking
    log("Trusted quote verification:");
    if (ecdsa_quote_verification(quote, true) != 0)
      ret = -1;

    printf("\n===========================================\n\n");
    // Unrusted quote verification, ignore error checking
    log("Untrusted quote verification:");

#else
    // Quote verification with QVL
    log("Quote verification with QVL, support both SGX and TDX quote:");
#endif

    if (ecdsa_quote_verification(quote, false) != 0)
      ret = -1;

#if defined(_MSC_VER)
    if (qpl_library_handle != NULL) {
        FreeLibrary(qpl_library_handle);
    }
#endif

    return ret;
}
