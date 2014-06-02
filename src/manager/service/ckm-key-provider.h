/*===========================================================================
 Name        : ckm_key_provider.h
 Author      : Kyungwook Tak
 Version     : 1.0
 Copyright   : Samsung Electronics
 Description :
    The libskmm.so library main header file.

    Central key manager Key Provider v1.0 library.

    Used PKCS5 PBKDF2 HMAC with SHA512 (16 bytes salt, 16384 iterations).
    Used AES256-GCM for encrypting and integrity checking.
    Used NIST SP 800-108 for Key Derivation Function (KDF). Counter mode.
    Used HMAC-SHA-512 for Pseudorandom Function (PRF).
  ===========================================================================*/
#ifndef CKM_KEY_PROVIDER_H_
#define CKM_KEY_PROVIDER_H_

#include <stdint.h>

/*===========================================================================
 *  Definitions of constants.
  ===========================================================================*/
#ifndef ERROR
#define ERROR                      -1   // The function return codes.
#endif
#ifndef SUCCESS
#define SUCCESS                     0
#endif
#ifndef INVALID_ARGUMENTS
#define INVALID_ARGUMENTS          -2
#endif
#ifndef MEMORY_ALLOCATION_ERROR
#define MEMORY_ALLOCATION_ERROR    -3
#endif
#ifndef NOT_INITIALIZED_ERROR
#define NOT_INITIALIZED_ERROR      -4   // The library not initialized error.
#endif
#ifndef SYSTEM_CALL_ERROR
#define SYSTEM_CALL_ERROR          -5
#endif
#ifndef OPENSSL_ENGINE_ERROR
#define OPENSSL_ENGINE_ERROR       -6
#endif
#ifndef VERIFY_DATA_ERROR
#define VERIFY_DATA_ERROR          -7
#endif
#ifndef NOT_ALLOWED_ERROR
#define NOT_ALLOWED_ERROR          -8
#endif
#ifndef PERMISSION_DENIED_ERROR
#define PERMISSION_DENIED_ERROR    -9
#endif
#ifndef LIBRARY_LOCKED_ERROR
#define LIBRARY_LOCKED_ERROR       -10
#endif

//  The check format of used data structures error codes.
#define DKEK_MAGIC_CODE_ERROR          -20
#define DKEK_VERSION_ERROR             -21
#define DKEK_KEY_LENGTH_ERROR          -22

//  Verify DKEK AES-GCM auth tag on 1St
//  stage (encrypt on PKEK2 Software Key) error.
#define DKEK_VERIFY_AUTH_TAG_1_ERROR   -23
//  Verify DKEK AES-GCM auth tag on 2Nd
//  stage (encrypt on Device Hardware Key with TZ trustlet) error.
#define DKEK_VERIFY_AUTH_TAG_2_ERROR   -24

#define DEK_MAGIC_CODE_ERROR           -25
#define DEK_VERSION_ERROR              -26
#define DEK_KEY_LENGTH_ERROR           -27

//  Verify DEK  AES-GCM auth tag (encrypt on KEK1 Software Key) error.
#define DEK_VERIFY_AUTH_TAG_ERROR      -28

//  The Device Firmware Integrity Check Errors with different policies.
#define INTEGRITY_CHECK_FAILURE        -90
#define INTEGRITY_CHECK_FAILURE_1      -91
#define INTEGRITY_CHECK_FAILURE_2      -92
#define INTEGRITY_CHECK_FAILURE_3      -93
#define INTEGRITY_CHECK_FAILURE_4      -94
#define INTEGRITY_CHECK_FAILURE_5      -95
#define INTEGRITY_CHECK_FAILURE_6      -96
#define INTEGRITY_CHECK_FAILURE_7      -97

//  Key protection options
#define KEY_FLAG_TZ_VERIFY_FIRMWARE 0x00000001  // Verify firmware integrity before decryption
#define KEY_FLAGS_RESERVED          0xFFFFFFF8  // Use different policies from 0...7 range.

//  Old definition of TrustZone-backed helper(for backward compatibility)
#define SKMM_QSEE_HELPER           ((char *)NULL)

//  The SKMM library initialization modes.
//  Default mode. Use cryptographically strong pseudo-random generator.
#define SKMM_DEFAULT_MODE           0
//  Testing mode. Use simple pseudo-random generator with reproducible sequence.
#define SKMM_TESTING_MODE          -1

#define AES128_KEY_LEN_BITS         128 // 128 bits
#define AES256_KEY_LEN_BITS         256 // 256 bits

#define AES128_KEY_LEN_BYTES       (AES128_KEY_LEN_BITS /  8)
#define AES256_KEY_LEN_BYTES       (AES256_KEY_LEN_BITS /  8)

#define PBKDF2_SALT_LEN             16
#define PBKDF2_ITERATIONS           16384

//  The max length of random seed for OpenSSL engine.
#define MIN_RANDOM_SEED_LEN         48
#define MAX_RANDOM_SEED_LEN         256

#define DFT_RANDOM_SEED_LEN         MIN_RANDOM_SEED_LEN
#define RANDOM_SEED_LEN             256

//  The default size of AES-GCM tag (auth tag).
#define AES_GCM_TAG_SIZE            16

#define MAX_IV_SIZE                 16
#define MAX_SALT_SIZE               16
//  256 bits
#define MAX_KEY_SIZE                32
//  256 bits  + authtag, use keyInfo as AAD.
#define MAX_WRAPPED_KEY_SIZE        64
#define KEY_MATERIAL_INFO_SIZE      256

#define MAX_LABEL_SIZE              32
//  The max Label Size. Application Label or Domain Name.
#define DOMAIN_NAME_SIZE            (MAX_LABEL_SIZE)
#define APP_LABEL_SIZE              (MAX_LABEL_SIZE)

#define MAX_CONTEXT_SIZE            64

/*===========================================================================
 *  Definitions of data types.
  ===========================================================================*/
//  The size of this element must be equal to KEY_MATERIAL_INFO_SIZE.
typedef struct __attribute__((packed)) KeyMaterialInfo_ {
    uint32_t        keyLength;
    char            label[MAX_LABEL_SIZE]; 	// Domain name or app label.
    uint8_t         context[MAX_CONTEXT_SIZE]; // Hash of app specific information.
    uint8_t         iv1[MAX_IV_SIZE];    	// Initialization vector for 1St stage (encrypt on PKEK2 Software Key).
    uint8_t         salt[MAX_SALT_SIZE];    // The salt used with PKCS5 PBKDF2 HMAC with SHA512.
    uint32_t        policy;    				// Additional key protection options
    uint8_t         reserved[KEY_MATERIAL_INFO_SIZE - // Reserved for future use
                             sizeof(uint32_t) * 2 - MAX_LABEL_SIZE -
                             MAX_CONTEXT_SIZE - MAX_IV_SIZE *  2 -  MAX_SALT_SIZE];
    uint8_t         iv2[MAX_IV_SIZE];		// Initialization vector for 2Nd stage (encrypt on Device Hardware Key with TZ trustlet).
} KeyMaterialInfo;
                           /* for raw key */
typedef struct __attribute__((packed)) KeyMaterial_ {
    KeyMaterialInfo keyInfo;
    uint8_t         key[MAX_KEY_SIZE];
} KeyMaterial;
                           /* for wrapped key */
typedef struct __attribute__((packed)) WrappedKeyMaterial_ {
    uint32_t        magicCode;
    uint32_t        version;
    KeyMaterialInfo keyInfo;
    uint8_t         wrappedKey[MAX_WRAPPED_KEY_SIZE];
} WrappedKeyMaterial;

/*===========================================================================
 *  Prototypes of global functions.
  ===========================================================================*/
#ifdef  __cplusplus
extern "C" {
#endif

int SKMMInitializeLibrary(int  InitMode,
    char *SKMMHelperModule,
    uint8_t  RandomSeed[MAX_RANDOM_SEED_LEN]);
int SKMMCloseLibrary(void);

int SKMMisHardwareBacked(void);

/*  Domain KEK Management Funstions */
int GenerateDomainKEK(
	WrappedKeyMaterial *DKEK,
    const char *password,
    const uint32_t keyLength,
    const char domain[DOMAIN_NAME_SIZE]);

int GenerateDomainKEKWithPolicy(
	WrappedKeyMaterial *DKEK,
    const char *password,
    const uint32_t keyLength,
    const char domain[DOMAIN_NAME_SIZE],
    uint32_t policy);

int UpdateDomainKEK(
	WrappedKeyMaterial *DKEK,
    const WrappedKeyMaterial *old_DKEK,
    const char *old_pw,
    const char *new_pw);

int SetDomainKEKPolicy(
	KeyMaterial *raw_DKEK,
    uint32_t policy);

int UnwrapDomainKEK(
	KeyMaterial *raw_DKEK,
    const WrappedKeyMaterial *DKEK,
    const char *password);

int WrapDomainKEK(
	WrappedKeyMaterial *DKEK,
    const KeyMaterial *raw_DKEK,
    const char *password);

int VerifyDomainKEK(
	const WrappedKeyMaterial *DKEK,
    const char *password);

/*  Application KEK Management Functions  */
int GenerateDEK(WrappedKeyMaterial *DEK,
    const KeyMaterial *raw_DKEK,
    const char appLabel[APP_LABEL_SIZE],
    const char context[MAX_CONTEXT_SIZE]);

int UnwrapDEK(KeyMaterial *raw_DEK,
    const KeyMaterial *raw_DKEK,
    const WrappedKeyMaterial *DEK);
#if 0
int WrapDEK(KeyMaterial *raw_DEK,
    const KeyMaterial *raw_DKEK,
    const WrappedKeyMaterial *DEK);
#endif
#ifdef  __cplusplus
}
#endif

#endif                                  // SKMM_H_
