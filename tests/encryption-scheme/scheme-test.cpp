/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file       scheme-test.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */
#include <scheme-test.h>

#include <sys/smack.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <fstream>
#include <string>
#include <stdexcept>

#include <smack-access.h>

using namespace CKM;
using namespace std;

namespace {
const uid_t UID = 7654;
const gid_t GID = 7654;
const char* const DBPASS = "db-pass";
const char* const LABEL = "my-label";

const string TEST_DATA = "test-data";
const char* const DATA_ALIAS1 = "data-alias1";
const char* const DATA_ALIAS2 = "data-alias2";
const char* const KEY_RSA_PRV_ALIAS1 = "key-rsa-prv-alias1";
const char* const KEY_RSA_PRV_ALIAS2 = "key-rsa-prv-alias2";
const char* const KEY_RSA_PRV_ALIAS3 = "key-rsa-prv-alias3";
const char* const KEY_RSA_PRV_ALIAS4 = "key-rsa-prv-alias4";
const char* const KEY_RSA_PUB_ALIAS1 = "key-rsa-pub-alias1";
const char* const KEY_RSA_PUB_ALIAS2 = "key-rsa-pub-alias2";
const char* const KEY_RSA_PUB_ALIAS3 = "key-rsa-pub-alias3";
const char* const KEY_RSA_PUB_ALIAS4 = "key-rsa-pub-alias4";
const char* const KEY_AES_ALIAS1 = "key-aes-alias1";
const char* const KEY_AES_ALIAS2 = "key-aes-alias2";
const char* const KEY_AES_ALIAS3 = "key-aes-alias3";
const char* const KEY_AES_ALIAS4 = "key-aes-alias4";
const char* const CERT_ROOT_ALIAS1 = "cert-root-alias1";
const char* const CERT_ROOT_ALIAS2 = "cert-root-alias2";
const char* const CERT_ROOT_ALIAS3 = "cert-root-alias3";
const char* const CERT_ROOT_ALIAS4 = "cert-root-alias4";
const char* const CERT_IM_CA_ALIAS1 = "cert-im-ca-alias1";
const char* const CERT_IM_CA_ALIAS2 = "cert-im-ca-alias2";
const char* const CERT_IM_CA_ALIAS3 = "cert-im-ca-alias3";
const char* const CERT_IM_CA_ALIAS4 = "cert-im-ca-alias4";
const char* const CERT_LEAF_ALIAS1 = "cert-leaf-alias1";
const char* const CERT_LEAF_ALIAS2 = "cert-leaf-alias2";
const char* const CERT_LEAF_ALIAS3 = "cert-leaf-alias3";
const char* const CERT_LEAF_ALIAS4 = "cert-leaf-alias4";
const char* const PKCS_ALIAS1 = "pkcs-alias1";
const char* const PKCS_ALIAS2 = "pkcs-alias2";
const char* const PKCS_ALIAS3 = "pkcs-alias3";
const char* const PKCS_ALIAS4 = "pkcs-alias4";
const Password TEST_PASS = "custom user password";

// TEST_ROOT_CA, expires 2035
std::string TEST_ROOT_CA =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDnzCCAoegAwIBAgIJAMH/ADkC5YSTMA0GCSqGSIb3DQEBBQUAMGYxCzAJBgNV\n"
    "BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMQ0wCwYDVQQKDARBQ01FMRAwDgYD\n"
    "VQQLDAdUZXN0aW5nMSEwHwYDVQQDDBhUZXN0IHJvb3QgY2EgY2VydGlmaWNhdGUw\n"
    "HhcNMTQxMjMwMTcyMTUyWhcNMjQxMjI3MTcyMTUyWjBmMQswCQYDVQQGEwJBVTET\n"
    "MBEGA1UECAwKU29tZS1TdGF0ZTENMAsGA1UECgwEQUNNRTEQMA4GA1UECwwHVGVz\n"
    "dGluZzEhMB8GA1UEAwwYVGVzdCByb290IGNhIGNlcnRpZmljYXRlMIIBIjANBgkq\n"
    "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0EJRdUtd2th0vTVF7QxvDKzyFCF3w9vC\n"
    "9IDE/Yr12w+a9jd0s7/eG96qTHIYffS3B7x2MB+d4n+SR3W0qmYh7xk8qfEgH3da\n"
    "eDoV59IZ9r543KM+g8jm6KffYGX1bIJVVY5OhBRbO9nY6byYpd5kbCIUB6dCf7/W\n"
    "rQl1aIdLGFIegAzPGFPXDcU6F192686x54bxt/itMX4agHJ9ZC/rrTBIZghVsjJo\n"
    "5/AH5WZpasv8sfrGiiohAxtieoYoJkv5MOYP4/2lPlOY+Cgw1Yoz+HHv31AllgFs\n"
    "BquBb/kJVmCCNsAOcnvQzTZUsW/TXz9G2nwRdqI1nSy2JvVjZGsqGQIDAQABo1Aw\n"
    "TjAdBgNVHQ4EFgQUt6pkzFt1PZlfYRL/HGnufF4frdwwHwYDVR0jBBgwFoAUt6pk\n"
    "zFt1PZlfYRL/HGnufF4frdwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOC\n"
    "AQEAld7Qwq0cdzDQ51w1RVLwTR8Oy25PB3rzwEHcSGJmdqlMi3xOdaz80S1R1BBX\n"
    "ldvGBG5Tn0vT7xSuhmSgI2/HnBpy9ocHVOmhtNB4473NieEpfTYrnGXrFxu46Wus\n"
    "9m/ZnugcQ2G6C54A/NFtvgLmaC8uH8M7gKdS6uYUwJFQEofkjmd4UpOYSqmcRXhS\n"
    "Jzd5FYFWkJhKJYp3nlENSOD8CUFFVGekm05nFN2gRVc/qaqQkEX77+XYvhodLRsV\n"
    "qMn7nf7taidDKLO2T4bhujztnTYOhhaXKgPy7AtZ28N2wvX96VyAPB/vrchGmyBK\n"
    "kOg11TpPdNDkhb1J4ZCh2gupDg==\n"
    "-----END CERTIFICATE-----\n";

// TEST_IM_CA, signed by TEST_ROOT_CA, expires 2035
std::string TEST_IM_CA =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDljCCAn6gAwIBAgICEAAwDQYJKoZIhvcNAQEFBQAwZjELMAkGA1UEBhMCQVUx\n"
    "EzARBgNVBAgMClNvbWUtU3RhdGUxDTALBgNVBAoMBEFDTUUxEDAOBgNVBAsMB1Rl\n"
    "c3RpbmcxITAfBgNVBAMMGFRlc3Qgcm9vdCBjYSBjZXJ0aWZpY2F0ZTAeFw0xNTAx\n"
    "MTYxNjQ1MzRaFw0zNTAxMTExNjQ1MzRaMGQxCzAJBgNVBAYTAkFVMRMwEQYDVQQI\n"
    "DApTb21lLVN0YXRlMQ0wCwYDVQQKDARBQ01FMRAwDgYDVQQLDAdUZXN0aW5nMR8w\n"
    "HQYDVQQDDBZUZXN0IElNIENBIGNlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEF\n"
    "AAOCAQ8AMIIBCgKCAQEAzmBF78qClgoKfnLAncMXZwZ14TW+5kags1+QCYeg3c7j\n"
    "L9+RvDxIaX2tKf1sukJcwQfYqUlQkwt+58LMOb2ORtkpj8Or6WCWCZ0BzneT8ug7\n"
    "nxJT4m9+bohMF0JoKjjB2H4KNMHamLIwUxRKt6nyfk81kVhJOi2vzzxd+UCPi6Pc\n"
    "UAbJNH48eNgOIg55nyFovVzYj8GIo/9GvHJj83PPa/KlJZ+Z1qZASZZ/VYorplVT\n"
    "thsHXKfejhFy5YJ9t7n/vyAQsyBsagZsvX19xnH41fbYXHKf8UbXG23rNaZlchs6\n"
    "XJVLQdzOpj3WTj/lCocVHqLaZISLhNQ3aI7kUBUdiwIDAQABo1AwTjAdBgNVHQ4E\n"
    "FgQUoCYNaCBP4jl/3SYQuK8Ka+6i3QEwHwYDVR0jBBgwFoAUt6pkzFt1PZlfYRL/\n"
    "HGnufF4frdwwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOCAQEAjRzWiD97\n"
    "Htv4Kxpm3P+C+xP9AEteCJfO+7p8MWgtWEJOknJyt55zeKS2JwZIq57KcbqD8U7v\n"
    "vAUx1ymtUhlFPFd7J1mJ3pou+3aFYmGShYhGHpbrmUwjp7HVP588jrW1NoZVHdMc\n"
    "4OgJWFrViXeu9+maIcekjMB/+9Y0dUgQuK5ZuT5H/Jwet7Th/o9uufTUZjBzRvrB\n"
    "pbXgQpqgME2av4Q/6LuldPCTHLtWXgFUU2R+yCGmuGilvhFJnKoQryAbYnIQNWE8\n"
    "SLoHQ9s1i7Zyb7HU6UAaqMOz15LBkyAqtNyJcO2p7Q/p5YK0xfD4xisI5qXucqVm\n"
    "F2obL5qJSTN/RQ==\n"
    "-----END CERTIFICATE-----\n";

// TEST_LEAF, signed by TEST_IM_CA, expires 2035
std::string TEST_LEAF =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDOzCCAiMCAQEwDQYJKoZIhvcNAQEFBQAwZDELMAkGA1UEBhMCQVUxEzARBgNV\n"
    "BAgMClNvbWUtU3RhdGUxDTALBgNVBAoMBEFDTUUxEDAOBgNVBAsMB1Rlc3Rpbmcx\n"
    "HzAdBgNVBAMMFlRlc3QgSU0gQ0EgY2VydGlmaWNhdGUwHhcNMTUwMTE2MTY0ODE0\n"
    "WhcNMzUwMTExMTY0ODE0WjBjMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1T\n"
    "dGF0ZTENMAsGA1UECgwEQUNNRTEQMA4GA1UECwwHVGVzdGluZzEeMBwGA1UEAwwV\n"
    "VGVzdCBsZWFmIGNlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
    "CgKCAQEAzTdDIa2tDmRxFnIgiG+mBz8GoSVODs0ImNQGbqj+pLhBOFRH8fsah4Jl\n"
    "z5YF9KwhMVLknnHGFLE/Nb7Ac35kEzhMQMpTRxohW83oxw3eZ8zN/FBoKqg4qHRq\n"
    "QR8kS10YXTgrBR0ex/Vp+OUKEw6h7yL2r4Tpvrn9/qHwsxtLxqWbDIVf1O9b1Lfc\n"
    "bllYMdmV5E62yN5tcwrDP8gvHjFnVeLzrG8wTpc9FR90/0Jkfp5jAJcArOBLrT0E\n"
    "4VRqs+4HuwT8jAwFAmNnc7IYX5qSjtSWkmmHe73K/lzB+OiI0JEc/3eWUTWqwTSk\n"
    "4tNCiQGBKJ39LXPTBBJdzmxVH7CUDQIDAQABMA0GCSqGSIb3DQEBBQUAA4IBAQAp\n"
    "UdDOGu3hNiG+Vn10aQ6B1ZmOj3t+45gUV3sC+y8hB8EK1g4P5Ke9bVDts0T5eOnj\n"
    "CSc+6VoND5O4adI0IFFRFljHNVnvjeosHfUZNnowsmA2ptQBtC1g5ZKRvKXlkC5/\n"
    "i5BGgRqPFA7y9WB9Y05MrJHf3E+Oz/RBsLeeNiNN+rF5X1vYExvGHpo0M0zS0ze9\n"
    "HtC0aOy8ocsTrQkf3ceHTAXx2i8ftoSSD4klojtWFpWMrNQa52F7wB9nU6FfKRuF\n"
    "Zj/T1JkYXKkEwZU6nAR2jdZp3EP9xj3o15V/tyFcXHx6l8NTxn4cJb+Xe4VquQJz\n"
    "6ON7PVe0ABN/AlwVQiFE\n"
    "-----END CERTIFICATE-----\n";

enum {
    NO_PASS = 0,
    PASS = 1
};

enum {
    NO_EXP = 0,
    EXP = 1
};

// [password][exportable]
Policy policy[2][2] = {
        {{ Password(), false }, { Password(), true }},
        {{ TEST_PASS,  false }, { TEST_PASS,  true }},
};
} // namespace std


SchemeTest::SchemeTest() {
    m_control = Control::create();
    m_mgr = Manager::create();
}

SchemeTest::~SchemeTest() {
    seteuid(0);
    setegid(0);

    m_control->lockUserKey(UID);
}

void SchemeTest::SetupUser() {
    if(CKM_API_SUCCESS != m_control->lockUserKey(UID))
        throw runtime_error("lockUserKey failed");

    if(CKM_API_SUCCESS != m_control->removeUserData(UID))
        throw runtime_error("removeUserData failed");

    if(CKM_API_SUCCESS != m_control->unlockUserKey(UID, DBPASS))
        throw runtime_error("unlockUserKey failed");

    SmackAccess sa;
    sa.add("System", LABEL, "w");
    sa.add(LABEL, "System", "w");
    sa.apply();

    if(0 > smack_set_label_for_self(LABEL))
        throw runtime_error("smack_set_label_for_self failed");

    if(0 > setegid(GID))
        throw runtime_error("setegid failed");

    if(0 >  seteuid(UID))
        throw runtime_error("seteuid failed");
}

void SchemeTest::FillDb() {
    RawBuffer dataBuffer(TEST_DATA.begin(), TEST_DATA.end());

    if(CKM_API_SUCCESS != m_mgr->saveData(DATA_ALIAS1, dataBuffer, policy[NO_PASS][EXP]))
        throw runtime_error("saveData 1 failed");
    if(CKM_API_SUCCESS != m_mgr->saveData(DATA_ALIAS2, dataBuffer, policy[PASS][EXP]))
        throw runtime_error("saveData 2 failed");


    if(CKM_API_SUCCESS != m_mgr->createKeyPairRSA(1024,
                                                  KEY_RSA_PRV_ALIAS1,
                                                  KEY_RSA_PUB_ALIAS1,
                                                  policy[NO_PASS][NO_EXP],
                                                  policy[NO_PASS][NO_EXP]))
        throw runtime_error("createKeyPair 1 failed");
    if(CKM_API_SUCCESS != m_mgr->createKeyPairRSA(1024,
                                                  KEY_RSA_PRV_ALIAS2,
                                                  KEY_RSA_PUB_ALIAS2,
                                                  policy[NO_PASS][EXP],
                                                  policy[NO_PASS][EXP]))
        throw runtime_error("createKeyPair 2 failed");
    if(CKM_API_SUCCESS != m_mgr->createKeyPairRSA(1024,
                                                  KEY_RSA_PRV_ALIAS3,
                                                  KEY_RSA_PUB_ALIAS3,
                                                  policy[PASS][NO_EXP],
                                                  policy[PASS][NO_EXP]))
        throw runtime_error("createKeyPair 3 failed");
    if(CKM_API_SUCCESS != m_mgr->createKeyPairRSA(1024,
                                                  KEY_RSA_PRV_ALIAS4,
                                                  KEY_RSA_PUB_ALIAS4,
                                                  policy[PASS][EXP],
                                                  policy[PASS][EXP]))
        throw runtime_error("createKeyPair 4 failed");


    if(CKM_API_SUCCESS != m_mgr->createKeyAES(128, KEY_AES_ALIAS1, policy[NO_PASS][NO_EXP]))
        throw runtime_error("createKeyAES 1 failed");
    if(CKM_API_SUCCESS != m_mgr->createKeyAES(128, KEY_AES_ALIAS2, policy[NO_PASS][EXP]))
        throw runtime_error("createKeyAES 2 failed");
    if(CKM_API_SUCCESS != m_mgr->createKeyAES(128, KEY_AES_ALIAS3, policy[PASS][NO_EXP]))
        throw runtime_error("createKeyAES 3 failed");
    if(CKM_API_SUCCESS != m_mgr->createKeyAES(128, KEY_AES_ALIAS4, policy[PASS][EXP]))
        throw runtime_error("createKeyAES 4 failed");


    CKM::RawBuffer rootCaBuffer(TEST_ROOT_CA.begin(), TEST_ROOT_CA.end());
    CKM::CertificateShPtr rootCa = CKM::Certificate::create(rootCaBuffer,
                                                            CKM::DataFormat::FORM_PEM);

    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_ROOT_ALIAS1, rootCa, policy[NO_PASS][NO_EXP]))
        throw runtime_error("saveCertificate 1  failed");
    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_ROOT_ALIAS2, rootCa, policy[NO_PASS][EXP]))
        throw runtime_error("saveCertificate 2  failed");
    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_ROOT_ALIAS3, rootCa, policy[PASS][NO_EXP]))
        throw runtime_error("saveCertificate 3  failed");
    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_ROOT_ALIAS4, rootCa, policy[PASS][EXP]))
        throw runtime_error("saveCertificate 4  failed");


    CKM::RawBuffer imCaBuffer(TEST_IM_CA.begin(), TEST_IM_CA.end());
    CKM::CertificateShPtr imCa = CKM::Certificate::create(imCaBuffer, CKM::DataFormat::FORM_PEM);

    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_IM_CA_ALIAS1, imCa, policy[NO_PASS][NO_EXP]))
        throw runtime_error("saveCertificate 5  failed");
    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_IM_CA_ALIAS2, imCa, policy[NO_PASS][EXP]))
        throw runtime_error("saveCertificate 6  failed");
    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_IM_CA_ALIAS3, imCa, policy[PASS][NO_EXP]))
        throw runtime_error("saveCertificate 7  failed");
    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_IM_CA_ALIAS4, imCa, policy[PASS][EXP]))
        throw runtime_error("saveCertificate 8  failed");


    CKM::RawBuffer leafBuffer(TEST_LEAF.begin(), TEST_LEAF.end());
    CKM::CertificateShPtr leaf = CKM::Certificate::create(leafBuffer, CKM::DataFormat::FORM_PEM);

    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_LEAF_ALIAS1, leaf, policy[NO_PASS][NO_EXP]))
        throw runtime_error("saveCertificate 9  failed");
    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_LEAF_ALIAS2, leaf, policy[NO_PASS][EXP]))
        throw runtime_error("saveCertificate 10 failed");
    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_LEAF_ALIAS3, leaf, policy[PASS][NO_EXP]))
        throw runtime_error("saveCertificate 11 failed");
    if(CKM_API_SUCCESS != m_mgr->saveCertificate(CERT_LEAF_ALIAS4, leaf, policy[PASS][EXP]))
        throw runtime_error("saveCertificate 12 failed");


    ifstream is("/usr/share/ckm-test/pkcs.p12");
    istreambuf_iterator<char> begin(is), end;
    RawBuffer pkcsBuffer(begin, end);

    auto pkcs = PKCS12::create(pkcsBuffer, Password());
    if(CKM_API_SUCCESS != m_mgr->savePKCS12(PKCS_ALIAS1,
                                            pkcs,
                                            policy[NO_PASS][NO_EXP],
                                            policy[NO_PASS][NO_EXP]))
        throw runtime_error("savePkcs12 1 failed");
    if(CKM_API_SUCCESS != m_mgr->savePKCS12(PKCS_ALIAS2,
                                            pkcs,
                                            policy[NO_PASS][NO_EXP],
                                            policy[NO_PASS][EXP]))
        throw runtime_error("savePkcs12 2 failed");
    if(CKM_API_SUCCESS != m_mgr->savePKCS12(PKCS_ALIAS3,
                                            pkcs,
                                            policy[NO_PASS][NO_EXP],
                                            policy[PASS][NO_EXP]))
        throw runtime_error("savePkcs12 3 failed");
    if(CKM_API_SUCCESS != m_mgr->savePKCS12(PKCS_ALIAS4,
                                            pkcs,
                                            policy[NO_PASS][NO_EXP],
                                            policy[PASS][EXP]))
        throw runtime_error("savePkcs12 4 failed");
}
