#include <new>
#include <string.h>
#include <dpl/log/log.h>

#include <key-provider.h>
#include <ckm/ckm-type.h>

#define KEY_LENGTH 	32
#define CONTEXT		"SAMPLE_CONTEXT_OF_APP"

namespace {

template<typename T>
CKM::RawBuffer toRawBuffer(const T &data) {
    CKM::RawBuffer output;
    const unsigned char *ptr = reinterpret_cast<const unsigned char*>(&data);
    output.assign(ptr, ptr + sizeof(T));
    return output;
}

// You cannot use toRawBuffer template with pointers
template<typename T>
CKM::RawBuffer toRawBuffer(T *) {
    class NoPointerAllowed { NoPointerAllowed(){} };
    NoPointerAllowed a;
    return CKM::RawBuffer();
}

} // anonymous namespace

using namespace CKM;

bool KeyProvider::s_isInitialized = false;

KeyProvider::KeyProvider()
  : m_rawDKEK(NULL)
  , m_isInitialized(false)
{}

KeyProvider::KeyProvider(
    const RawBuffer &domainKEKInWrapForm,
    const std::string &password)
  : m_rawDKEK(NULL)
  , m_isInitialized(true)
{
    LogDebug("Constructor");

    if (!s_isInitialized) {
        throw std::string("SKMM was not initialize. Object couldn't be created");
    }

    if (!m_isInitialized) {
        throw std::string("Object not initialized!");
    }

    if (domainKEKInWrapForm.size() != sizeof(WrappedKeyMaterial)) {
        LogDebug("input size:" << domainKEKInWrapForm.size()
          << " Expected: " << sizeof(WrappedKeyMaterial));
        throw std::string("buffer doesn't have proper size to store "
          "WrappedKeyMaterial in KeyProvider Constructor");
    }

    WrappedKeyMaterial DKEK;
    m_rawDKEK = new KeyMaterial;

    memcpy(&DKEK, domainKEKInWrapForm.data(), sizeof(WrappedKeyMaterial));

    if(!VerifyDomainKEK(&DKEK, password.c_str()) &&
      !UnwrapDomainKEK(m_rawDKEK, &DKEK, password.c_str()))
    {
        LogDebug("UnwrapDomainKEK SUCCESS");
        LogDebug("keyInfo.label : " << m_rawDKEK->keyInfo.label);
        LogDebug("key           : " << m_rawDKEK->key);
    } else {
        LogDebug("VerifyDKEK or UnwrapDKEK failed");
        delete m_rawDKEK;
        throw std::string("VerifyDKEK or UnwrapDKEK failed in KeyProvider Constructor");
    }
}

KeyProvider& KeyProvider::operator=(KeyProvider &&second) {
    if (this == &second)
        return *this;
    m_isInitialized = second.m_isInitialized;
    m_rawDKEK = second.m_rawDKEK;
    second.m_isInitialized = false;
    second.m_rawDKEK = NULL;
    return *this;
}

KeyProvider::KeyProvider(KeyProvider &&second) {
    m_isInitialized = second.m_isInitialized;
    m_rawDKEK = second.m_rawDKEK;
    second.m_isInitialized = false;
    second.m_rawDKEK = NULL;
}

bool KeyProvider::isInitialized() {
    return m_isInitialized;
}

KeyAES KeyProvider::getDomainKEK(){
    if(!m_isInitialized) {
        throw std::string("Object not initialized!");
    }

    RawBuffer rawData_rawDKEK;
    rawData_rawDKEK.clear();

    rawData_rawDKEK = toRawBuffer(*m_rawDKEK);

    // TODO: rawData_rawDKEK is not safe. Memory it's not overwritten in destructor we should probably pass this key in other way.
    // TODO: convert to KeyAES(rawData_rawDEK) after key-aes implementation done
    return KeyAES();
    //	return KeyAES(rawData_rawDKEK);
}

RawBuffer KeyProvider::getDomainKEK(const std::string &password){
    if(!m_isInitialized) {
        throw std::string("Object not initialized!");
    }

    RawBuffer domainKEKInWrapForm;
    WrappedKeyMaterial DKEK;

    if (!WrapDomainKEK(&DKEK, m_rawDKEK, password.c_str())) {
        LogDebug("WrapDomainKEK Success");
        LogDebug("keyInfo.label : " << DKEK.keyInfo.label);
        LogDebug("key           : " << DKEK.wrappedKey);

        domainKEKInWrapForm = toRawBuffer(DKEK);
    } else {
        LogDebug("WrapDKEK failed");
        throw std::string("WrapDKEK Failed in KeyProvider::getDomainKEK");
    }
    return domainKEKInWrapForm;
}


// API name changed.
// from KeyAES KeyProvider::decryptDEK(const RawBuffer &encryptedDEKInWrapForm)
KeyAES KeyProvider::unwrapDEK(const RawBuffer &DEKInWrapForm){
    if(!m_isInitialized) {
        throw std::string("Object not initialized!");
    }

    if(DEKInWrapForm.size() != sizeof(WrappedKeyMaterial)){
        throw std::string("buffer doesn't have proper size to store WrappedKeyMaterial in KeyProvider::unwrapDEK");
    }

    RawBuffer rawData_rawDEK;
    rawData_rawDEK.clear();

    KeyMaterial rawDEK;
    WrappedKeyMaterial DEK;

    memcpy(&DEK, DEKInWrapForm.data(), sizeof(WrappedKeyMaterial));
    if(!UnwrapDEK(&rawDEK, m_rawDKEK, &DEK)){
        LogDebug("UnwrapDEK SUCCESS");
        LogDebug("keyInfo.label : " << rawDEK.keyInfo.label);
        LogDebug("key           : " << rawDEK.key);

        rawData_rawDEK = toRawBuffer(rawDEK);
    }
    else{
        LogDebug("UnwrapDEK failed");
        throw std::string("UnwrapDEK Failed in KeyProvider::unwrapDEK");
    }

    // TODO: convert to KeyAES(rawData_rawDEK) after key-aes implementation done
    // TODO: it may not be secure to use RawData here
    return KeyAES();
    // return KeyAES(rawData_rawDEK);
}

RawBuffer KeyProvider::generateDEK(const std::string &smackLabel){
    if(!m_isInitialized) {
        throw std::string("Object not initialized!");
    }
    RawBuffer DEKInWrapForm;
    WrappedKeyMaterial *DEK;
    DEKInWrapForm.clear();
    DEK = new WrappedKeyMaterial;

    if(smackLabel.length() < APP_LABEL_SIZE){
        if(!GenerateDEK(DEK, m_rawDKEK,
              smackLabel.c_str(),
              CONTEXT)){
            LogDebug("GenerateDEK Success");
			DEKInWrapForm = toRawBuffer(*DEK);
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
			DEKInWrapForm = toRawBuffer(*DEK);
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
	const std::string &oldPass,
	const std::string &newPass)
{
    if(domainKEKInWrapForm.size() != sizeof(WrappedKeyMaterial)){
        throw std::string("buffer doesn't have proper size to store WrappedKeyMaterial in KeyProvider::reencrypt");

    }

    WrappedKeyMaterial old_DKEK;
    WrappedKeyMaterial new_DKEK;
    RawBuffer rawData_DKEK;
    rawData_DKEK.clear();
    memcpy(&old_DKEK, domainKEKInWrapForm.data(), sizeof(WrappedKeyMaterial));

    if(!VerifyDomainKEK(&old_DKEK, oldPass.c_str()) &&
      !UpdateDomainKEK(&new_DKEK, &old_DKEK,
          oldPass.c_str(), newPass.c_str()))
    {
        LogDebug("VerifyDKEK and UpdateDKEK SUCCESS");
        LogDebug("keyInfo.label : " << new_DKEK.keyInfo.label);
        LogDebug("key           : " << new_DKEK.wrappedKey);

        rawData_DKEK = toRawBuffer(new_DKEK);
    } else {
        LogDebug("VerifyDKEK or UpdateDKEK Failed");
        throw std::string("VerifyDKEK or UpdateDKEK Failed in KeyProvider::reencrypt");
    }

    // TODO overwrite keys
    return rawData_DKEK;
}


RawBuffer KeyProvider::generateDomainKEK(
    const std::string &user,
    const std::string &userPassword)
{
    RawBuffer domainKEKInWrapForm;
    WrappedKeyMaterial DKEK;

    if(!GenerateDomainKEK(&DKEK, userPassword.c_str(), KEY_LENGTH, user.c_str())){
        LogDebug("GenerateDKEK Success");
        LogDebug("keyInfo.label : " << DKEK.keyInfo.label);
        LogDebug("key           : " << DKEK.wrappedKey);

        domainKEKInWrapForm = toRawBuffer(DKEK);
    } else{
        LogDebug("GenerateDomainKEK Failed");
        throw std::string("GenerateDomainKEK Failed in KeyProvider::generateDomainKEK");
    }

    LogDebug("DomainKekInWrapForm.size()=" << domainKEKInWrapForm.size());
    return domainKEKInWrapForm;
}

int KeyProvider::initializeLibrary(){
    if(!SKMMInitializeLibrary(SKMM_TESTING_MODE, NULL, NULL)){
        LogDebug("SKMMInitializeLibrary Success");
        s_isInitialized = true;
        return SUCCESS;
    }
    LogDebug("SKMMInitializeLibrary Failed");
    return ERROR;
}

int KeyProvider::closeLibrary(){
    if(!SKMMCloseLibrary()){
        LogDebug("SKMMCloseLibrary Success");
        s_isInitialized = false;
        return SUCCESS;
    }
    LogDebug("SKMMCloseLibrary Failed");
    return ERROR;
}

KeyProvider::~KeyProvider(){
    LogDebug("KeyProvider Destructor");
    if (m_rawDKEK) {
        // overwrite key
        char *ptr = reinterpret_cast<char*>(m_rawDKEK);
        for (size_t size = 0; size < sizeof(KeyMaterial); ++size)
            ptr[size] = 0;
        // verification
        for (size_t size = 0; size < sizeof(KeyMaterial); ++size) {
            if (0 != ptr[size]) {
                LogError("Key was not destroyed!");
                break;
            }
        }
    }
    delete m_rawDKEK;
}

