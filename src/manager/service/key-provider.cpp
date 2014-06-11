#include <key-provider.h>
#include <ckm/ckm-type.h>
#include <string.h>
#include <dpl/log/log.h>

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

class KeyMaterialContainer{
public:
    class Exception {
    public:
        DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
    };
    KeyMaterialContainer(){
        keyMaterial = new KeyMaterial;
    }
    KeyMaterial& getKeyMaterial(){
        return *keyMaterial;
    }
    ~KeyMaterialContainer(){
        // overwrite key
        char *ptr = reinterpret_cast<char*>(keyMaterial);
        for (size_t size = 0; size < sizeof(KeyMaterial); ++size)
            ptr[size] = 0;
        // verification
        for (size_t size = 0; size < sizeof(KeyMaterial); ++size) {
            if (0 != ptr[size]) {
                delete keyMaterial;
                ThrowMsg(Exception::Base, "KeyMaterial in KeyMaterialContainer "
                    "was not destroyed!");
            }
        }
        delete keyMaterial;
    }
private:
    KeyMaterial *keyMaterial;
};

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
    if (!s_isInitialized) {
    	ThrowMsg(Exception::InitFailed, "SKMM should be initialized first");
    }
    if (!m_isInitialized) {
        ThrowMsg(Exception::InitFailed, "Object not initialized!. Should not happened");
    }
    if (domainKEKInWrapForm.size() != sizeof(WrappedKeyMaterial)) {
        LogError("input size:" << domainKEKInWrapForm.size()
          << " Expected: " << sizeof(WrappedKeyMaterial));
        ThrowMsg(Exception::InputParamError, "buffer doesn't have proper size to store "
          "WrappedKeyMaterial in KeyProvider Constructor");
    }

    WrappedKeyMaterial DKEK;
    m_rawDKEK = new KeyMaterial;

    memcpy(&DKEK, domainKEKInWrapForm.data(), sizeof(WrappedKeyMaterial));

	if(VerifyDomainKEK(&DKEK, password.c_str()))
		ThrowMsg(Exception::UnwrapFailed, "VerifyDomainKEK failed in KeyProvider Constructor");

	if(UnwrapDomainKEK(m_rawDKEK, &DKEK, password.c_str()))
		ThrowMsg(Exception::UnwrapFailed, "UnwrapDomainKEK failed in KeyProvider Constructor");
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

RawBuffer KeyProvider::getPureDomainKEK(){
    if(!m_isInitialized) {
        ThrowMsg(Exception::InitFailed, "Object not initialized!");
    }

	// TODO secure
	return RawBuffer(m_rawDKEK->key, (m_rawDKEK->key) + m_rawDKEK->keyInfo.keyLength);
}

RawBuffer KeyProvider::getWrappedDomainKEK(const std::string &password){
    if(!m_isInitialized) {
        ThrowMsg(Exception::InitFailed, "Object not initialized!");
    }

    WrappedKeyMaterial DKEK;
    if (WrapDomainKEK(&DKEK, m_rawDKEK, password.c_str())){
        ThrowMsg(Exception::InitFailed, "WrapDKEK Failed in KeyProvider::getDomainKEK");
		return RawBuffer();
    }
	
	LogDebug("getDomainKEK(password) Success");
	return toRawBuffer(DKEK);
}


KeyAES KeyProvider::unwrapDEK(const RawBuffer &DEKInWrapForm){
    if(!m_isInitialized) {
        ThrowMsg(Exception::InitFailed, "Object not initialized!");
    }

    if(DEKInWrapForm.size() != sizeof(WrappedKeyMaterial)){
    	LogError("input size:" << DEKInWrapForm.size()
    	          << " Expected: " << sizeof(WrappedKeyMaterial));
        ThrowMsg(Exception::InputParamError,
        		"buffer doesn't have proper size to store "
        		"WrappedKeyMaterial in KeyProvider::unwrapDEK");
    }

	KeyMaterialContainer keyMaterialContainer = KeyMaterialContainer();
    WrappedKeyMaterial DEK;

    memcpy(&DEK, DEKInWrapForm.data(), sizeof(WrappedKeyMaterial));
    if(UnwrapDEK(&(keyMaterialContainer.getKeyMaterial()), m_rawDKEK, &DEK)){
		ThrowMsg(Exception::UnwrapFailed,
			"UnwrapDEK Failed in KeyProvider::unwrapDEK");
		return KeyAES();
    }

	LogDebug("unwrapDEK SUCCESS");

	// TODO: it may not be secure to use RawData here
	// [k.tak] RawBuffer local variable is removed.
	// KeyMaterialContainer added. (to destruct KeyMaterial after returning)
	// It will be modified to return toRawBuffer result value
	// after key-aes implementation done
	return KeyAES();
	//return KeyAES(toRawBuffer(keyMaterialContainer.getKeyMaterial()));
}

RawBuffer KeyProvider::generateDEK(const std::string &smackLabel){
    if(!m_isInitialized) {
        ThrowMsg(Exception::InitFailed,
        		"Object not initialized!");
    }
    WrappedKeyMaterial DEK;
	std::string resized_smackLabel;

	if(smackLabel.length() < APP_LABEL_SIZE)
		resized_smackLabel = smackLabel;
	else
		resized_smackLabel = smackLabel.substr(0, APP_LABEL_SIZE-1);

	if(GenerateDEK(&DEK, m_rawDKEK, resized_smackLabel.c_str(), CONTEXT)){
		ThrowMsg(Exception::GenFailed, 
			"GenerateDEK Failed in KeyProvider::generateDEK");
		return RawBuffer();
	}

	LogDebug("GenerateDEK Success");
	return toRawBuffer(DEK);
}

RawBuffer KeyProvider::reencrypt(
	const RawBuffer &domainKEKInWrapForm,
	const std::string &oldPass,
	const std::string &newPass)
{
    if(domainKEKInWrapForm.size() != sizeof(WrappedKeyMaterial)){
    	LogError("input size:" << domainKEKInWrapForm.size()
    	          << " Expected: " << sizeof(WrappedKeyMaterial));
    	ThrowMsg(Exception::InputParamError,
        		"buffer doesn't have proper size to store "
        		"WrappedKeyMaterial in KeyProvider::reencrypt");
	}

    WrappedKeyMaterial old_DKEK;
    WrappedKeyMaterial new_DKEK;
    memcpy(&old_DKEK, domainKEKInWrapForm.data(), sizeof(WrappedKeyMaterial));

	if(VerifyDomainKEK(&old_DKEK, oldPass.c_str()))
	{
		ThrowMsg(Exception::UnwrapFailed,
			"VerifyDomainKEK in KeyProvider::reencrypt Failed");
		return RawBuffer();
	}
	if(UpdateDomainKEK(&new_DKEK, &old_DKEK, 
			oldPass.c_str(), newPass.c_str()))
	{
		ThrowMsg(Exception::UnwrapFailed,
			"UpdateDomainKEK in KeyProvider::reencrypt Failed");
		return RawBuffer();
	}

	LogDebug("reencrypt SUCCESS");
	return toRawBuffer(new_DKEK);
}


RawBuffer KeyProvider::generateDomainKEK(
    const std::string &user,
    const std::string &userPassword)
{
    WrappedKeyMaterial DKEK;

    if(GenerateDomainKEK(&DKEK, userPassword.c_str(), 
		KEY_LENGTH, user.c_str()))
	{
		ThrowMsg(Exception::GenFailed,
			"GenerateDomainKEK Failed in KeyProvider::generateDomainKEK");
		return RawBuffer();
    }

	LogDebug("generateDomainKEK Success");
	return toRawBuffer(DKEK);
}

int KeyProvider::initializeLibrary(){
    if(SKMMInitializeLibrary(SKMM_TESTING_MODE, NULL, NULL)){
		ThrowMsg(Exception::InitFailed, "SKMMInitializeLibrary Failed");
		return ERROR;
    }

	LogDebug("initializeLibrary Success");
	s_isInitialized = true;
	return SUCCESS;
}

int KeyProvider::closeLibrary(){
    if(SKMMCloseLibrary()){
		ThrowMsg(Exception::InitFailed, "SKMMCloseLibrary Failed");
		return ERROR;
    }

	LogDebug("closeLibrary Success");
	s_isInitialized = false;
	return SUCCESS;
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
                delete m_rawDKEK;
                ThrowMsg(Exception::Base, "Key was not destroyed!");
            }
        }
    }
    delete m_rawDKEK;
}

