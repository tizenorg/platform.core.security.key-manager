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

WrappedKeyMaterialContainer::WrappedKeyMaterialContainer(){
	wrappedKeyMaterial = new WrappedKeyMaterial;
	memset(wrappedKeyMaterial, 0, sizeof(WrappedKeyMaterial));
}
WrappedKeyMaterialContainer::WrappedKeyMaterialContainer(const unsigned char *data){
	wrappedKeyMaterial = new WrappedKeyMaterial;
	memcpy(wrappedKeyMaterial, data, sizeof(WrappedKeyMaterial));
}
WrappedKeyMaterial& WrappedKeyMaterialContainer::getWrappedKeyMaterial(){
	return *wrappedKeyMaterial;
}
WrappedKeyMaterialContainer::~WrappedKeyMaterialContainer(){
	delete wrappedKeyMaterial;
}

KeyMaterialContainer::KeyMaterialContainer(){
	keyMaterial = new KeyMaterial;
	memset(keyMaterial, 0, sizeof(KeyMaterial));
}
KeyMaterialContainer::KeyMaterialContainer(const unsigned char *data){
	keyMaterial = new KeyMaterial;
	memcpy(keyMaterial, data, sizeof(KeyMaterial));
}
KeyMaterial& KeyMaterialContainer::getKeyMaterial(){
	return *keyMaterial;
}
KeyMaterialContainer::~KeyMaterialContainer(){
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

bool KeyProvider::s_isInitialized = false;

KeyProvider::KeyProvider()
	: m_kmcDKEK(NULL)
	, m_isInitialized(false){}

KeyProvider::KeyProvider(
	const RawBuffer &domainKEKInWrapForm,
	const std::string &password)
	: m_kmcDKEK(new KeyMaterialContainer())
	, m_isInitialized(true)
{
	if (!s_isInitialized){
		ThrowMsg(Exception::InitFailed, "SKMM should be initialized first");
	}
	if (!m_isInitialized){
		ThrowMsg(Exception::InitFailed, "Object not initialized!. Should not happened");
	}
	if (domainKEKInWrapForm.size() != sizeof(WrappedKeyMaterial)){
		LogError("input size:" << domainKEKInWrapForm.size()
			<< " Expected: " << sizeof(WrappedKeyMaterial));
		ThrowMsg(Exception::InputParamError, "buffer doesn't have proper size to store WrappedKeyMaterial in KeyProvider Constructor");
	}
	WrappedKeyMaterialContainer wkmcDKEK = WrappedKeyMaterialContainer(domainKEKInWrapForm.data());

	if(VerifyDomainKEK(&(wkmcDKEK.getWrappedKeyMaterial()), password.c_str()))
		ThrowMsg(Exception::UnwrapFailed, "VerifyDomainKEK failed in KeyProvider Constructor");
	if(UnwrapDomainKEK(&(m_kmcDKEK->getKeyMaterial()), &(wkmcDKEK.getWrappedKeyMaterial()), password.c_str()))
		ThrowMsg(Exception::UnwrapFailed, "UnwrapDomainKEK failed in KeyProvider Constructor");

}

KeyProvider& KeyProvider::operator=(KeyProvider &&second){
	if (this == &second)
		return *this;
	m_isInitialized = second.m_isInitialized;
	m_kmcDKEK = second.m_kmcDKEK;
	second.m_isInitialized = false;
	second.m_kmcDKEK = NULL;
	return *this;
}

KeyProvider::KeyProvider(KeyProvider &&second) {
	m_isInitialized = second.m_isInitialized;
	m_kmcDKEK = second.m_kmcDKEK;
	second.m_isInitialized = false;
}

bool KeyProvider::isInitialized() {
	return m_isInitialized;
}

RawBuffer KeyProvider::getPureDomainKEK(){
	if(!m_isInitialized){
		ThrowMsg(Exception::InitFailed, "Object not initialized!");
	}

	// TODO secure
	return RawBuffer(m_kmcDKEK->getKeyMaterial().key, (m_kmcDKEK->getKeyMaterial().key) + m_kmcDKEK->getKeyMaterial().keyInfo.keyLength);
}

RawBuffer KeyProvider::getWrappedDomainKEK(const std::string &password){
	if(!m_isInitialized) {
		ThrowMsg(Exception::InitFailed, "Object not initialized!");
	}

	WrappedKeyMaterialContainer wkmcDKEK = WrappedKeyMaterialContainer();

	if(WrapDomainKEK(&(wkmcDKEK.getWrappedKeyMaterial()), &(m_kmcDKEK->getKeyMaterial()), password.c_str())){
		ThrowMsg(Exception::InitFailed, "WrapDKEK Failed in KeyProvider::getDomainKEK");
		return RawBuffer();
	}
	
	LogDebug("getDomainKEK(password) Success");
	return toRawBuffer(wkmcDKEK.getWrappedKeyMaterial());
}


RawBuffer KeyProvider::getPureDEK(const RawBuffer &DEKInWrapForm){
	if(!m_isInitialized) {
		ThrowMsg(Exception::InitFailed, "Object not initialized!");
	}

	if(DEKInWrapForm.size() != sizeof(WrappedKeyMaterial)){
		LogError("input size:" << DEKInWrapForm.size()
				  << " Expected: " << sizeof(WrappedKeyMaterial));
		ThrowMsg(Exception::InputParamError,
				"buffer doesn't have proper size to store "
				"WrappedKeyMaterial in KeyProvider::getPureDEK");
	}

	KeyMaterialContainer kmcDEK = KeyMaterialContainer();
	WrappedKeyMaterialContainer wkmcDEK = WrappedKeyMaterialContainer(DEKInWrapForm.data());

	if(UnwrapDEK(&(kmcDEK.getKeyMaterial()), &(m_kmcDKEK->getKeyMaterial()), &(wkmcDEK.getWrappedKeyMaterial()))){
		ThrowMsg(Exception::UnwrapFailed,
			"UnwrapDEK Failed in KeyProvider::getPureDEK");
	}

	LogDebug("getPureDEK SUCCESS");

	return RawBuffer(
		kmcDEK.getKeyMaterial().key,
		(kmcDEK.getKeyMaterial().key) + kmcDEK.getKeyMaterial().keyInfo.keyLength);
}

RawBuffer KeyProvider::generateDEK(const std::string &smackLabel){
	if(!m_isInitialized) {
		ThrowMsg(Exception::InitFailed,
				"Object not initialized!");
	}
	WrappedKeyMaterialContainer wkmcDEK = WrappedKeyMaterialContainer();
	std::string resized_smackLabel;

	if(smackLabel.length() < APP_LABEL_SIZE)
		resized_smackLabel = smackLabel;
	else
		resized_smackLabel = smackLabel.substr(0, APP_LABEL_SIZE-1);

	if(GenerateDEK(&(wkmcDEK.getWrappedKeyMaterial()), &(m_kmcDKEK->getKeyMaterial()), resized_smackLabel.c_str(), CONTEXT)){
		ThrowMsg(Exception::GenFailed, 
			"GenerateDEK Failed in KeyProvider::generateDEK");
		return RawBuffer();
	}

	LogDebug("GenerateDEK Success");
	return toRawBuffer(wkmcDEK.getWrappedKeyMaterial());
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

	WrappedKeyMaterialContainer wkmcOldDEK = WrappedKeyMaterialContainer(domainKEKInWrapForm.data());
	WrappedKeyMaterialContainer wkmcNewDEK = WrappedKeyMaterialContainer();

	if(VerifyDomainKEK(&(wkmcOldDEK.getWrappedKeyMaterial()), oldPass.c_str()))
	{
		ThrowMsg(Exception::UnwrapFailed,
			"VerifyDomainKEK in KeyProvider::reencrypt Failed");
		return RawBuffer();
	}
	if(UpdateDomainKEK(
			&(wkmcNewDEK.getWrappedKeyMaterial()),
			&(wkmcOldDEK.getWrappedKeyMaterial()),
			oldPass.c_str(), newPass.c_str()))
	{
		ThrowMsg(Exception::UnwrapFailed,
			"UpdateDomainKEK in KeyProvider::reencrypt Failed");
		return RawBuffer();
	}

	LogDebug("reencrypt SUCCESS");
	return toRawBuffer(wkmcNewDEK.getWrappedKeyMaterial());
}


RawBuffer KeyProvider::generateDomainKEK(
	const std::string &user,
	const std::string &userPassword)
{
	WrappedKeyMaterialContainer wkmcDKEK = WrappedKeyMaterialContainer();

	if(GenerateDomainKEK(&(wkmcDKEK.getWrappedKeyMaterial()), userPassword.c_str(), KEY_LENGTH, user.c_str()))
	{
		ThrowMsg(Exception::GenFailed,
			"GenerateDomainKEK Failed in KeyProvider::generateDomainKEK");
		return RawBuffer();
	}

	LogDebug("generateDomainKEK Success");
	return toRawBuffer(wkmcDKEK.getWrappedKeyMaterial());
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
	delete m_kmcDKEK;
}

