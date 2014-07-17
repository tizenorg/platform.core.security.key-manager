#include <key-provider.h>
#include <ckm/ckm-type.h>
#include <string.h>
#include <dpl/log/log.h>
#define KEY_LENGTH 	32
#define CONTEXT		"SAMPLE_CONTEXT_OF_APP"

namespace {

template<typename T>
CKM::SafeBuffer toSafeBufferConversion(const T &data) {
	CKM::SafeBuffer output;
	const unsigned char *ptr = reinterpret_cast<const unsigned char*>(&data);
	output.assign(ptr, ptr + sizeof(T));
	return output;
}

// You cannot use toSafeBufferConversion template with pointers
template<typename T>
CKM::SafeBuffer toSafeBufferConversion(T *) {
	class NoPointerAllowed { NoPointerAllowed(){} };
	NoPointerAllowed a;
	return CKM::SafeBuffer();
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
	, m_isInitialized(false)
{
    LogDebug("Created empty KeyProvider");
}

KeyProvider::KeyProvider(
	const SafeBuffer &domainKEKInWrapForm,
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
		ThrowMsg(Exception::PassWordError, "VerifyDomainKEK failed in KeyProvider Constructor");
	if(UnwrapDomainKEK(&(m_kmcDKEK->getKeyMaterial()), &(wkmcDKEK.getWrappedKeyMaterial()), password.c_str()))
		ThrowMsg(Exception::UnwrapFailed, "UnwrapDomainKEK failed in KeyProvider Constructor");
}

KeyProvider& KeyProvider::operator=(KeyProvider &&second){
    LogDebug("Moving KeyProvider");
	if (this == &second)
		return *this;
	m_isInitialized = second.m_isInitialized;
	m_kmcDKEK = second.m_kmcDKEK;
	second.m_isInitialized = false;
	second.m_kmcDKEK = NULL;
	return *this;
}

KeyProvider::KeyProvider(KeyProvider &&second) {
    LogDebug("Moving KeyProvider");
	m_isInitialized = second.m_isInitialized;
	m_kmcDKEK = second.m_kmcDKEK;
	second.m_isInitialized = false;
    second.m_kmcDKEK = NULL;
}

bool KeyProvider::isInitialized() {
	return m_isInitialized;
}

SafeBuffer KeyProvider::getPureDomainKEK(){
	if(!m_isInitialized){
		ThrowMsg(Exception::InitFailed, "Object not initialized!");
	}

	// TODO secure
	return SafeBuffer(m_kmcDKEK->getKeyMaterial().key, (m_kmcDKEK->getKeyMaterial().key) + m_kmcDKEK->getKeyMaterial().keyInfo.keyLength);
}

SafeBuffer KeyProvider::getWrappedDomainKEK(const std::string &password){
	if(!m_isInitialized) {
		ThrowMsg(Exception::InitFailed, "Object not initialized!");
	}

	WrappedKeyMaterialContainer wkmcDKEK = WrappedKeyMaterialContainer();

	if(WrapDomainKEK(&(wkmcDKEK.getWrappedKeyMaterial()), &(m_kmcDKEK->getKeyMaterial()), password.c_str())){
		ThrowMsg(Exception::InitFailed, "WrapDKEK Failed in KeyProvider::getDomainKEK");
		return SafeBuffer();
	}
	
	LogDebug("getDomainKEK(password) Success");
	return toSafeBufferConversion(wkmcDKEK.getWrappedKeyMaterial());
}


SafeBuffer KeyProvider::getPureDEK(const SafeBuffer &DEKInWrapForm){
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

	return SafeBuffer(
		kmcDEK.getKeyMaterial().key,
		(kmcDEK.getKeyMaterial().key) + kmcDEK.getKeyMaterial().keyInfo.keyLength);
}

SafeBuffer KeyProvider::generateDEK(const std::string &smackLabel){
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
		return SafeBuffer();
	}

	LogDebug("GenerateDEK Success");
	return toSafeBufferConversion(wkmcDEK.getWrappedKeyMaterial());
}

SafeBuffer KeyProvider::reencrypt(
	const SafeBuffer &domainKEKInWrapForm,
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
		ThrowMsg(Exception::PassWordError,
			"Incorrect Old Password ");
		return SafeBuffer();
	}
	if(UpdateDomainKEK(
			&(wkmcNewDEK.getWrappedKeyMaterial()),
			&(wkmcOldDEK.getWrappedKeyMaterial()),
			oldPass.c_str(), newPass.c_str()))
	{
		ThrowMsg(Exception::UnwrapFailed,
			"UpdateDomainKEK in KeyProvider::reencrypt Failed");
		return SafeBuffer();
	}

	LogDebug("reencrypt SUCCESS");
	return toSafeBufferConversion(wkmcNewDEK.getWrappedKeyMaterial());
}


SafeBuffer KeyProvider::generateDomainKEK(
	const std::string &user,
	const std::string &userPassword)
{
	WrappedKeyMaterialContainer wkmcDKEK = WrappedKeyMaterialContainer();

	if(GenerateDomainKEK(&(wkmcDKEK.getWrappedKeyMaterial()), userPassword.c_str(), KEY_LENGTH, user.c_str()))
	{
		ThrowMsg(Exception::GenFailed,
			"GenerateDomainKEK Failed in KeyProvider::generateDomainKEK");
		return SafeBuffer();
	}

	LogDebug("generateDomainKEK Success");
	return toSafeBufferConversion(wkmcDKEK.getWrappedKeyMaterial());
}

int KeyProvider::initializeLibrary(){
	if(SKMMInitializeLibrary(SKMM_DEFAULT_MODE, NULL, NULL)){
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

