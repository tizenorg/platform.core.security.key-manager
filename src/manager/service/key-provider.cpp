#include <string.h>
#include <dpl/log/log.h>
#include <key-provider.h>

#define KEY_LENGTH 	32
#define CONTEXT		"SAMPLE_CONTEXT_OF_APP"

using namespace CKM;

int KeyProvider::s_isInitialized = 0;

KeyProvider::KeyProvider(
	const RawBuffer &domainKEKInWrapForm, 
	const RawBuffer &password){

	LogDebug("Constructor");
	
	if(!s_isInitialized){
		throw std::string("SKMM was not initialize. Object couldn't be created");
	}
	if(domainKEKInWrapForm.size() != sizeof(WrappedKeyMaterial)){
		throw std::string("buffer doesn't have proper size to store WrappedKeyMaterial in KeyProvider Constructor");
	}

	m_rawDKEK = new KeyMaterial;
	WrappedKeyMaterial *DKEK;
	DKEK = new WrappedKeyMaterial;

	memcpy(DKEK, domainKEKInWrapForm.data(), sizeof(WrappedKeyMaterial));
	if(!VerifyDomainKEK(DKEK, (const char *)password.data()) && 
		!UnwrapDomainKEK(m_rawDKEK, DKEK, (const char *)password.data())){
		LogDebug("UnwrapDomainKEK SUCCESS");
		LogDebug("keyInfo.label : " << m_rawDKEK->keyInfo.label);
		LogDebug("key           : " << m_rawDKEK->key);
		

		delete DKEK;
    }
	else{
		LogDebug("VerifyDKEK or UnwrapDKEK failed");
		delete DKEK;
		delete m_rawDKEK;
		throw std::string("VerifyDKEK or UnwrapDKEK failed in KeyProvider Constructor");
	}
}

KeyAES KeyProvider::getDomainKEK(){
	RawBuffer rawData_rawDKEK;
	rawData_rawDKEK.clear();

	rawData_rawDKEK.insert(
		rawData_rawDKEK.begin(),
		(const unsigned char *)m_rawDKEK,
		(const unsigned char *)(m_rawDKEK+sizeof(KeyMaterial)));

//	TODO: convert to KeyAES(rawData_rawDEK) after key-aes implementation done
	return KeyAES();
//	return KeyAES(rawData_rawDKEK);
}

RawBuffer KeyProvider::getDomainKEK(const std::string &password){
	RawBuffer domainKEKInWrapForm;
	WrappedKeyMaterial *DKEK;
	DKEK = new WrappedKeyMaterial;


	if(!WrapDomainKEK(DKEK, m_rawDKEK, password.c_str())){
		LogDebug("WrapDomainKEK Success");
		LogDebug("keyInfo.label : " << DKEK->keyInfo.label);
		LogDebug("key           : " << DKEK->wrappedKey);

		domainKEKInWrapForm.clear();
		domainKEKInWrapForm.insert(
			domainKEKInWrapForm.begin(),
			(const unsigned char *)DKEK,
			(const unsigned char *)(DKEK+sizeof(WrappedKeyMaterial)));

	}
	else{
		LogDebug("WrapDKEK failed");
		delete DKEK;
		throw std::string("WrapDKEK Failed in KeyProvider::getDomainKEK");
	}
	delete DKEK;
	return domainKEKInWrapForm;
}


// API name changed.
// from KeyAES KeyProvider::decryptDEK(const RawBuffer &encryptedDEKInWrapForm)
KeyAES KeyProvider::unwrapDEK(const RawBuffer &DEKInWrapForm){

	if(DEKInWrapForm.size() != sizeof(WrappedKeyMaterial)){
		throw std::string("buffer doesn't have proper size to store WrappedKeyMaterial in KeyProvider::unwrapDEK");
	}

	RawBuffer rawData_rawDEK;
	rawData_rawDEK.clear();
	KeyMaterial *rawDEK = new KeyMaterial;
	WrappedKeyMaterial *DEK = new WrappedKeyMaterial;

	memcpy(DEK, DEKInWrapForm.data(), sizeof(WrappedKeyMaterial));
	if(!UnwrapDEK(rawDEK, m_rawDKEK, DEK)){
		LogDebug("UnwrapDEK SUCCESS");
		LogDebug("keyInfo.label : " << rawDEK->keyInfo.label);
		LogDebug("key           : " << rawDEK->key);
		
		rawData_rawDEK.insert(
			rawData_rawDEK.begin(),
			(const unsigned char *)rawDEK,
			(const unsigned char *)(rawDEK+sizeof(KeyMaterial)));

	}
	else{
		LogDebug("UnwrapDEK failed");
		delete DEK;
		delete rawDEK;
		throw std::string("UnwrapDEK Failed in KeyProvider::unwrapDEK");
	}
	
	delete DEK;
	delete rawDEK;

//	TODO: convert to KeyAES(rawData_rawDEK) after key-aes implementation done
	return KeyAES();
//	return KeyAES(rawData_rawDEK);
}

RawBuffer KeyProvider::generateDEK(const std::string &smackLabel){
	RawBuffer DEKInWrapForm;
	WrappedKeyMaterial *DEK;
	DEKInWrapForm.clear();
	DEK = new WrappedKeyMaterial;

	if(smackLabel.length() < APP_LABEL_SIZE){
		if(!GenerateDEK(DEK, m_rawDKEK, 
			smackLabel.c_str(), 
			CONTEXT)){
			LogDebug("GenerateDEK Success");
			DEKInWrapForm.insert(
				DEKInWrapForm.begin(),
				(const unsigned char *)DEK,
				(const unsigned char *)(DEK+sizeof(WrappedKeyMaterial)));
		}
		else{
			LogDebug("GenerateDEK Failed");
			delete DEK;
			throw std::string("GenerateDEK Failed in KeyProvider::generateDEK");
		}
	}
	else{
		if(!GenerateDEK(DEK, m_rawDKEK, 
			smackLabel.substr(0, APP_LABEL_SIZE-1).c_str(), 
			CONTEXT)){
			LogDebug("GenerateDEK Success");
			DEKInWrapForm.insert(
				DEKInWrapForm.begin(),
				(const unsigned char *)DEK,
				(const unsigned char *)(DEK+sizeof(WrappedKeyMaterial)));

		}
		else{
			LogDebug("GenerateDEK Failed");
			delete DEK;
			throw std::string("GenerateDEK Failed in KeyProvider::generateDEK");
		}
	}

	LogDebug("keyInfo.label : " << DEK->keyInfo.label);
	LogDebug("key           : " << DEK->wrappedKey);

	delete DEK;
	return DEKInWrapForm;
}

RawBuffer KeyProvider::reencrypt(
	const RawBuffer &domainKEKInWrapForm,
	const RawBuffer &oldPass,
	const RawBuffer &newPass){

	if(domainKEKInWrapForm.size() != sizeof(WrappedKeyMaterial)){
		throw std::string("buffer doesn't have proper size to store WrappedKeyMaterial in KeyProvider::reencrypt");

	}

	WrappedKeyMaterial *old_DKEK = new WrappedKeyMaterial;
	WrappedKeyMaterial *new_DKEK = new WrappedKeyMaterial;
	RawBuffer rawData_DKEK;
	rawData_DKEK.clear();
	memcpy(old_DKEK, domainKEKInWrapForm.data(), sizeof(WrappedKeyMaterial));

	if(!VerifyDomainKEK(old_DKEK, (const char *)oldPass.data()) &&
		!UpdateDomainKEK(new_DKEK, old_DKEK, 
		(const char *)oldPass.data(), (const char *)newPass.data())){


		LogDebug("VerifyDKEK and UpdateDKEK SUCCESS");
		LogDebug("keyInfo.label : " << new_DKEK->keyInfo.label);
		LogDebug("key           : " << new_DKEK->wrappedKey);

		rawData_DKEK.insert(
			rawData_DKEK.begin(),
			(const unsigned char *)new_DKEK,
			(const unsigned char *)(new_DKEK+sizeof(WrappedKeyMaterial)));

	}
	else{
		LogDebug("VerifyDKEK or UpdateDKEK Failed");
		delete old_DKEK;
		delete new_DKEK;
		throw std::string("VerifyDKEK or UpdateDKEK Failed in KeyProvider::reencrypt");
	}
	

	delete old_DKEK;
	delete new_DKEK;
	return rawData_DKEK;
}


RawBuffer KeyProvider::generateDomainKEK(
	const std::string &user,
	const RawBuffer &userPassword){

	WrappedKeyMaterial *DKEK;
	RawBuffer domainKEKInWrapForm;
	DKEK = new WrappedKeyMaterial;

	
	if(!GenerateDomainKEK(DKEK, (const char *)userPassword.data(), KEY_LENGTH, user.c_str())){
		LogDebug("GenerateDKEK Success");
		LogDebug("keyInfo.label : " << DKEK->keyInfo.label);
		LogDebug("key           : " << DKEK->wrappedKey);

		domainKEKInWrapForm.insert(
			domainKEKInWrapForm.begin(),
			(const unsigned char *)DKEK,
			(const unsigned char *)(DKEK+sizeof(WrappedKeyMaterial)));

	}
	else{
		LogDebug("GenerateDomainKEK Failed");
		delete DKEK;
		throw std::string("GenerateDomainKEK Failed in KeyProvider::generateDomainKEK");
	}
	delete DKEK;
	return domainKEKInWrapForm;
}

int KeyProvider::initializeLibrary(){
	if(!SKMMInitializeLibrary(SKMM_TESTING_MODE, NULL, NULL)){
		LogDebug("SKMMInitializeLibrary Success");
		s_isInitialized = 1;
		return SUCCESS;
	}
	LogDebug("SKMMInitializeLibrary Failed");
	throw std::string("SKMMInitializeLibrary Failed");
	return ERROR;
}

int KeyProvider::closeLibrary(){
	if(!SKMMCloseLibrary()){
		LogDebug("SKMMCloseLibrary Success");
		s_isInitialized = 0;
		return SUCCESS;
	}
	LogDebug("SKMMCloseLibrary Failed");
	throw std::string("SKMMCloseLibrary Failed");
	return ERROR;
}

KeyProvider::~KeyProvider(){
	LogDebug("Destructor");
	delete m_rawDKEK;
}

