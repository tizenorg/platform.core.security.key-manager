/*
 * ckm-key-provider-dummy-3.0.c
 *
 *  Created on: Jun 3, 2014
 *      Author: tak
 */


#include <string.h>
#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <ckm-key-provider.h>

void handleErrors(){
	//printError
}

int encryptAes256Gcm(const unsigned char *plaintext, int plaintext_len, const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext, unsigned char *tag){

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. */
    if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MAX_IV_SIZE, NULL))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    /* Get the tag */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag))
        handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int decryptAes256Gcm(const unsigned char *ciphertext, int ciphertext_len, unsigned char *tag, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext){

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

/* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        handleErrors();

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) handleErrors();

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, MAX_IV_SIZE, NULL))
        handleErrors();

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, tag))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    if(!(ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len)))
		handleErrors();

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    }else{
        /* Verify failed */
        return -1;
    }
}

int SKMMInitializeLibrary(
	int InitMode,
	char *SKMMHelperModule,
	uint8_t RandomSeed[MAX_RANDOM_SEED_LEN]){

	printf("InitMode         : %d\n", InitMode);
	printf("SKMMHelperModule : %s\n", SKMMHelperModule);
	printf("RandomSeed       : %s\n", RandomSeed);

	return SUCCESS;
}

int SKMMCloseLibrary(void){
	return SUCCESS;
}

int SKMMisHardwareBacked(void){
	// need to check return value in SKMM library header
	return SUCCESS;
}

int GenerateDomainKEK(
	WrappedKeyMaterial *DKEK,
    const char *password,
    const uint32_t keyLength,
    const char domain[DOMAIN_NAME_SIZE]){

    uint8_t salt[PBKDF2_SALT_LEN], key[MAX_KEY_SIZE], iv1[MAX_IV_SIZE];
	uint8_t tag[AES_GCM_TAG_SIZE];
    uint8_t PKEK1[MAX_KEY_SIZE];
    int wrappedKeyLength, domain_len;
    char *pass_concat_domain;

	if(keyLength > MAX_KEY_SIZE){
		// keyLength is larger than maximum
		return ERROR;
	}

	if(!RAND_bytes(salt, PBKDF2_SALT_LEN))
		return OPENSSL_ENGINE_ERROR;
	if(!RAND_bytes(key, keyLength))
		return OPENSSL_ENGINE_ERROR;
	if(!RAND_bytes(iv1, MAX_IV_SIZE))
		return OPENSSL_ENGINE_ERROR;

	domain_len = strlen(domain) < DOMAIN_NAME_SIZE ?
		strlen(domain) : DOMAIN_NAME_SIZE-1;
	pass_concat_domain = (char *)malloc(strlen(password)+domain_len+1);
	strncpy(pass_concat_domain, password, strlen(password));
	pass_concat_domain[strlen(password)] = '\0';
	strncat(pass_concat_domain, domain, domain_len);
	pass_concat_domain[strlen(password)+domain_len] = '\0';

	memset(DKEK, 0, sizeof(WrappedKeyMaterial));

	if(!PKCS5_PBKDF2_HMAC_SHA1(
			pass_concat_domain,
			strlen(pass_concat_domain),
			salt,
			PBKDF2_SALT_LEN,
			PBKDF2_ITERATIONS,
			MAX_KEY_SIZE,
			PKEK1)){
		free(pass_concat_domain);
		return OPENSSL_ENGINE_ERROR;
	}
	free(pass_concat_domain);

	if(0 > (wrappedKeyLength = encryptAes256Gcm(
			key,
			keyLength,
			PKEK1,
			iv1,
			DKEK->wrappedKey,
			tag))){
		return OPENSSL_ENGINE_ERROR;
	}
	
	DKEK->keyInfo.keyLength = (unsigned int)wrappedKeyLength;
	memcpy(DKEK->keyInfo.iv1, iv1, MAX_IV_SIZE);
	memcpy(DKEK->keyInfo.salt, salt, PBKDF2_SALT_LEN);

	memcpy(DKEK->keyInfo.label, domain, domain_len);

	memcpy(DKEK->keyInfo.iv2, tag, AES_GCM_TAG_SIZE);

	return SUCCESS;
}


int GenerateDomainKEKWithPolicy(
	WrappedKeyMaterial *DKEK,
	const char *password,
	const uint32_t keyLength,
	const char domain[DOMAIN_NAME_SIZE],
	uint32_t policy){

	if(GenerateDomainKEK(DKEK, password, keyLength, domain))
		return ERROR;

	DKEK->keyInfo.policy = policy;
	return SUCCESS;
}

int UpdateDomainKEK(
	WrappedKeyMaterial *DKEK,
	const WrappedKeyMaterial *old_DKEK,
	const char *old_pw,
	const char *new_pw){

	KeyMaterial *raw_DKEK;
	raw_DKEK = (KeyMaterial *)malloc(sizeof(KeyMaterial));
	memset(DKEK, 0, sizeof(WrappedKeyMaterial));
	memset(raw_DKEK, 0, sizeof(KeyMaterial));

	if(UnwrapDomainKEK(raw_DKEK, old_DKEK, old_pw)){
		free(raw_DKEK);
		return ERROR;
	}
	if(WrapDomainKEK(DKEK, raw_DKEK, new_pw)){
		free(raw_DKEK);
		return ERROR;
	}

	free(raw_DKEK);
	return SUCCESS;
}

int SetDomainKEKPolicy(
	KeyMaterial *raw_DKEK,
	uint32_t policy){

	raw_DKEK->keyInfo.policy = policy;
	return SUCCESS;
}

int UnwrapDomainKEK(
	KeyMaterial *raw_DKEK,
	const WrappedKeyMaterial *DKEK,
	const char *password){

	char *pass_concat_domain;
	uint8_t tag[AES_GCM_TAG_SIZE];
	uint8_t PKEK1[MAX_KEY_SIZE];
	int keyLength;

	pass_concat_domain = (char *)malloc(strlen(password)+strlen(DKEK->keyInfo.label)+1);
	strncpy(pass_concat_domain, password, strlen(password));
	pass_concat_domain[strlen(password)] = '\0';
	strncat(pass_concat_domain, DKEK->keyInfo.label, strlen(DKEK->keyInfo.label));
	pass_concat_domain[strlen(password)+strlen(DKEK->keyInfo.label)] = '\0';
	
	memset(raw_DKEK, 0, sizeof(KeyMaterial));
	
	if(!PKCS5_PBKDF2_HMAC_SHA1(
			pass_concat_domain,
			strlen(pass_concat_domain),
			DKEK->keyInfo.salt,
			PBKDF2_SALT_LEN,
			PBKDF2_ITERATIONS,
			MAX_KEY_SIZE,
			PKEK1)){
		free(pass_concat_domain);
		return OPENSSL_ENGINE_ERROR;
	}
	free(pass_concat_domain);


	memcpy(tag, DKEK->keyInfo.iv2, MAX_IV_SIZE);


	if(0 > (keyLength = decryptAes256Gcm(
			DKEK->wrappedKey,
			DKEK->keyInfo.keyLength,
			tag, PKEK1, DKEK->keyInfo.iv1, raw_DKEK->key))){

		return VERIFY_DATA_ERROR;
	}
	memcpy(&(raw_DKEK->keyInfo), &(DKEK->keyInfo), sizeof(KeyMaterialInfo));
	raw_DKEK->keyInfo.keyLength = (unsigned int)keyLength;
    return SUCCESS;
}

int WrapDomainKEK(
	WrappedKeyMaterial *DKEK,
	const KeyMaterial *raw_DKEK,
	const char *password){

	uint8_t tag[AES_GCM_TAG_SIZE];
    uint8_t PKEK1[MAX_KEY_SIZE];
    int wrappedKeyLength;
    char *pass_concat_domain;

	pass_concat_domain = (char *)malloc(strlen(password)+strlen(raw_DKEK->keyInfo.label)+1);
    strncpy(pass_concat_domain, password, strlen(password));
    pass_concat_domain[strlen(password)] = '\0';
    strncat(pass_concat_domain, raw_DKEK->keyInfo.label, strlen(raw_DKEK->keyInfo.label));
    pass_concat_domain[strlen(password)+strlen(raw_DKEK->keyInfo.label)] = '\0';
	memset(DKEK, 0, sizeof(WrappedKeyMaterial));
	if(!PKCS5_PBKDF2_HMAC_SHA1(
			pass_concat_domain,
			strlen(pass_concat_domain),
			raw_DKEK->keyInfo.salt,
			PBKDF2_SALT_LEN,
			PBKDF2_ITERATIONS,
			MAX_KEY_SIZE,
			PKEK1)){
		free(pass_concat_domain);
		return OPENSSL_ENGINE_ERROR;
	}
	free(pass_concat_domain);

	memcpy(&(DKEK->keyInfo), &(raw_DKEK->keyInfo), sizeof(KeyMaterialInfo));

	if(0 > (wrappedKeyLength = encryptAes256Gcm(
			raw_DKEK->key,
			raw_DKEK->keyInfo.keyLength,
			PKEK1,
			raw_DKEK->keyInfo.iv1,
			DKEK->wrappedKey,
			tag))){
		return OPENSSL_ENGINE_ERROR;
	}

	memcpy(DKEK->keyInfo.iv2, tag, AES_GCM_TAG_SIZE);
	DKEK->keyInfo.keyLength = (unsigned int)wrappedKeyLength;

	return SUCCESS;
}

int VerifyDomainKEK(
	const WrappedKeyMaterial *DKEK,
	const char *password){

	char *pass_concat_domain;
	uint8_t tag[AES_GCM_TAG_SIZE];
	uint8_t PKEK1[MAX_KEY_SIZE];
	uint8_t key[MAX_KEY_SIZE];

	pass_concat_domain = (char *)malloc(strlen(password)+strlen(DKEK->keyInfo.label)+1);
	strncpy(pass_concat_domain, password, strlen(password));
	pass_concat_domain[strlen(password)] = '\0';
	strncat(pass_concat_domain, DKEK->keyInfo.label, strlen(DKEK->keyInfo.label));
	pass_concat_domain[strlen(password)+strlen(DKEK->keyInfo.label)] = '\0';

	if(!PKCS5_PBKDF2_HMAC_SHA1(
			pass_concat_domain,
			strlen(pass_concat_domain),
			DKEK->keyInfo.salt,
			PBKDF2_SALT_LEN,
			PBKDF2_ITERATIONS,
			MAX_KEY_SIZE,
			PKEK1)){
		free(pass_concat_domain);
		return OPENSSL_ENGINE_ERROR;
	}
	free(pass_concat_domain);

	memcpy(tag, DKEK->keyInfo.iv2, MAX_IV_SIZE);

	if(0 > decryptAes256Gcm(
			DKEK->wrappedKey,
			DKEK->keyInfo.keyLength,
			tag, PKEK1, DKEK->keyInfo.iv1, key)){
		return VERIFY_DATA_ERROR;
	}

    return SUCCESS;
}

int GenerateDEK(
	WrappedKeyMaterial *DEK,
	const KeyMaterial *raw_DKEK,
	const char appLabel[APP_LABEL_SIZE],
	const char context[MAX_CONTEXT_SIZE]){


	uint8_t key[MAX_KEY_SIZE], iv1[MAX_IV_SIZE], tag[AES_GCM_TAG_SIZE];
    uint8_t PKEK2[MAX_KEY_SIZE];
    int wrappedKeyLength, appLabel_len, context_len;

	appLabel_len = strlen(appLabel) < APP_LABEL_SIZE ?
		strlen(appLabel) : APP_LABEL_SIZE-1;
	context_len = strlen(context) < MAX_CONTEXT_SIZE ?
		strlen(context) : MAX_CONTEXT_SIZE-1;

	memset(DEK, 0, sizeof(WrappedKeyMaterial));

	if(!RAND_bytes(key, raw_DKEK->keyInfo.keyLength))
		return OPENSSL_ENGINE_ERROR;
	if(!RAND_bytes(iv1, MAX_IV_SIZE))
		return OPENSSL_ENGINE_ERROR;

	if(!PKCS5_PBKDF2_HMAC_SHA1(
			appLabel, appLabel_len,
			raw_DKEK->key, PBKDF2_SALT_LEN,
			PBKDF2_ITERATIONS,
			MAX_KEY_SIZE, PKEK2))
		return OPENSSL_ENGINE_ERROR;

	if(0 > (wrappedKeyLength = encryptAes256Gcm(
			key, raw_DKEK->keyInfo.keyLength,
			PKEK2, iv1, 
			DEK->wrappedKey, tag)))
		return OPENSSL_ENGINE_ERROR;
	DEK->keyInfo.keyLength = (unsigned int)wrappedKeyLength;
	memcpy(DEK->keyInfo.iv1, iv1, MAX_IV_SIZE);
	memcpy(DEK->keyInfo.salt, raw_DKEK->key, PBKDF2_SALT_LEN);

	memcpy(DEK->keyInfo.label, appLabel, appLabel_len);
	DEK->keyInfo.label[appLabel_len] = '\0';
	memcpy(DEK->keyInfo.context, context, context_len);
	DEK->keyInfo.context[context_len] = '\0';

	memcpy(DEK->keyInfo.iv2, tag, AES_GCM_TAG_SIZE);

    return SUCCESS;
}

int UnwrapDEK(KeyMaterial *raw_DEK,
	const KeyMaterial *raw_DKEK,
	const WrappedKeyMaterial *DEK){

	uint8_t tag[AES_GCM_TAG_SIZE];
	uint8_t PKEK2[MAX_KEY_SIZE];
	int keyLength;

	memset(raw_DEK, 0, sizeof(KeyMaterial));

	if(!PKCS5_PBKDF2_HMAC_SHA1(
			DEK->keyInfo.label, strlen(DEK->keyInfo.label),
			raw_DKEK->key, PBKDF2_SALT_LEN,
			PBKDF2_ITERATIONS,
			MAX_KEY_SIZE, PKEK2))
		return OPENSSL_ENGINE_ERROR;
	memcpy(tag, DEK->keyInfo.iv2, AES_GCM_TAG_SIZE);

	if(0 > (keyLength = decryptAes256Gcm(
			DEK->wrappedKey, DEK->keyInfo.keyLength,
			tag, PKEK2, DEK->keyInfo.iv1,
			raw_DEK->key)))
		return VERIFY_DATA_ERROR;

	memcpy(&(raw_DEK->keyInfo), &(DEK->keyInfo), sizeof(KeyMaterialInfo));
	raw_DEK->keyInfo.keyLength = (unsigned int)keyLength;

    return SUCCESS;
}
