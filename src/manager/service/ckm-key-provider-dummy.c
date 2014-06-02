#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <ckm-key-provider.h>

int SKMMInitializeLibrary(
	int InitMode, 
	char *SKMMHelperModule, 
	uint8_t RandomSeed[MAX_RANDOM_SEED_LEN]){
	printf("SKMM Initialized\n");
	printf("Size of KeyMaterialInfo    : %d\n", sizeof(KeyMaterialInfo));
	printf("Size of KeyMaterial        : %d\n", sizeof(KeyMaterial));
	printf("Size of WrappedKeyMaterial : %d\n", sizeof(WrappedKeyMaterial));

	printf("InitMode = %d\n", InitMode);
	printf("SKMMHelperModule = %s\n", SKMMHelperModule);
	printf("RandomSeed = %s\n", RandomSeed);


	return SUCCESS;
}

int SKMMCloseLibrary(void){
	printf("SKMM Closed\n");
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

    uint32_t i;
    uint8_t _key[MAX_KEY_SIZE];
    uint8_t xor_operand[MAX_KEY_SIZE];

	if(keyLength > MAX_KEY_SIZE){
		// keyLength is larger than maximum
		return ERROR;
	}

    memcpy(DKEK->keyInfo.label, domain, MAX_LABEL_SIZE);
	DKEK->keyInfo.keyLength = keyLength;
    for(i=0; i<keyLength; i++){
        if(i%2==1) memset(_key+i, 0, 1);
        else memset(_key+i, 1, 1);
    }

    memset(xor_operand, 0, keyLength);
	memcpy(xor_operand, password, 
			strlen(password) < keyLength ? strlen(password) : keyLength);

    for(i=0; i<keyLength; i++){
        DKEK->wrappedKey[i] = _key[i] ^ xor_operand[i];
    }
    
    return SUCCESS;

}


int GenerateDomainKEKWithPolicy(
	WrappedKeyMaterial *DKEK,
	const char *password,
	const uint32_t keyLength,
	const char domain[DOMAIN_NAME_SIZE],
	uint32_t policy){

    uint32_t i;
    uint8_t _key[MAX_KEY_SIZE];
    uint8_t xor_operand[MAX_KEY_SIZE];

	if(keyLength > MAX_KEY_SIZE){
		// keyLength is larger than maximum
		return ERROR;
	}

    memcpy(DKEK->keyInfo.label, domain, MAX_LABEL_SIZE);
	DKEK->keyInfo.keyLength = keyLength;
	DKEK->keyInfo.policy = policy;

    for(i=0; i<keyLength; i++){
        if(i%2==1) memset(_key+i, 0, 1);
        else memset(_key+i, 1, 1);
    }

    memset(xor_operand, 0, keyLength);
    memcpy(xor_operand, password, 
            strlen(password) < keyLength ? strlen(password) : keyLength);

    for(i=0; i<keyLength; i++){
        DKEK->wrappedKey[i] = _key[i] ^ xor_operand[i];
    }
    
    return SUCCESS;

}

int UpdateDomainKEK(
	WrappedKeyMaterial *DKEK,
	const WrappedKeyMaterial *old_DKEK,
	const char *old_pw,
	const char *new_pw){
	
	KeyMaterial *raw_DKEK;
	raw_DKEK = (KeyMaterial *)malloc(sizeof(KeyMaterial));

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

    uint32_t i;
    uint8_t xor_operand[MAX_KEY_SIZE];

	memset(xor_operand, 0, MAX_KEY_SIZE);
    memcpy(xor_operand, password, 
			strlen(password) < MAX_KEY_SIZE ? strlen(password) : MAX_KEY_SIZE);
	
    for(i=0; i<DKEK->keyInfo.keyLength; i++){
        raw_DKEK->key[i] = DKEK->wrappedKey[i] ^ xor_operand[i];
    }
	memcpy(&(raw_DKEK->keyInfo), &(DKEK->keyInfo), sizeof(KeyMaterialInfo));

    return SUCCESS;		
}

int WrapDomainKEK(
	WrappedKeyMaterial *DKEK,
	const KeyMaterial *raw_DKEK,
	const char *password){

	uint32_t i;
	uint8_t xor_operand[MAX_KEY_SIZE];

	memset(xor_operand, 0, MAX_KEY_SIZE);
	memcpy(xor_operand, password,
			strlen(password) < MAX_KEY_SIZE ? strlen(password) : MAX_KEY_SIZE);

	for(i=0; i<raw_DKEK->keyInfo.keyLength; i++){
		DKEK->wrappedKey[i] = raw_DKEK->key[i] ^ xor_operand[i];
	}
	
	memcpy(&(DKEK->keyInfo), &(raw_DKEK->keyInfo), sizeof(KeyMaterialInfo));
	
	return SUCCESS;
}

int VerifyDomainKEK(
	const WrappedKeyMaterial *DKEK,
	const char *password){

	uint32_t i;
	uint8_t _key[MAX_KEY_SIZE];
	uint8_t xor_operand[MAX_KEY_SIZE];
	uint8_t xor_result[MAX_KEY_SIZE];

	memset(xor_result, 0, MAX_KEY_SIZE);
	memset(xor_operand, 0, MAX_KEY_SIZE);
	memcpy(xor_operand, password,
			strlen(password) < MAX_KEY_SIZE ? strlen(password) : MAX_KEY_SIZE);

	for(i=0; i<DKEK->keyInfo.keyLength; i++){
		xor_result[i] = DKEK->wrappedKey[i] ^ xor_operand[i];
	}

	for(i=0; i<DKEK->keyInfo.keyLength; i++){
        if(i%2==1) memset(_key+i, 0, 1);
        else memset(_key+i, 1, 1);
    }

	if(!memcmp(xor_result, _key, DKEK->keyInfo.keyLength))
		return SUCCESS;
	else
		return ERROR;
}

int GenerateDEK(
	WrappedKeyMaterial *DEK,
	const KeyMaterial *raw_DKEK,
	const char appLabel[APP_LABEL_SIZE],
	const char context[MAX_CONTEXT_SIZE]){
	
	uint32_t i;
	uint8_t _key[MAX_KEY_SIZE];
	uint8_t xor_operand[MAX_KEY_SIZE];

	memcpy(DEK->keyInfo.label, appLabel, APP_LABEL_SIZE);

	memcpy(DEK->keyInfo.context, context, MAX_CONTEXT_SIZE);
	DEK->keyInfo.keyLength = raw_DKEK->keyInfo.keyLength;


	for(i=0; i<DEK->keyInfo.keyLength; i++){
		if(i%2==0) memset(_key+i, 0, 1);
		else memset(_key+i, 1, 1);
	}
	memcpy(xor_operand, raw_DKEK, MAX_KEY_SIZE);
	for(i=0; i<DEK->keyInfo.keyLength; i++){
		DEK->wrappedKey[i] = _key[i] ^ xor_operand[i];
	}
	
	return SUCCESS;		
}

int UnwrapDEK(KeyMaterial *raw_DEK,
	const KeyMaterial *raw_DKEK,
	const WrappedKeyMaterial *DEK){

	uint32_t i;
	uint8_t xor_operand[MAX_KEY_SIZE];
	uint8_t wrapped_key[MAX_KEY_SIZE];

	memcpy(xor_operand, raw_DKEK, MAX_KEY_SIZE);
	memcpy(wrapped_key, DEK->wrappedKey, MAX_KEY_SIZE);
	for(i=0; i<raw_DKEK->keyInfo.keyLength; i++){
		raw_DEK->key[i] = wrapped_key[i] ^ xor_operand[i];
	}
	memcpy(&(raw_DEK->keyInfo), &(DEK->keyInfo), sizeof(KeyMaterialInfo));
	
    return SUCCESS;
}
