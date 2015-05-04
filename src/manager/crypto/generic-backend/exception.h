#pragma once

#include <dpl/exception.h>

namespace CKM {
namespace Crypto {
namespace Exception {

DECLARE_EXCEPTION_TYPE(CKM::Exception, Base)
DECLARE_EXCEPTION_TYPE(Base, InternalError)
DECLARE_EXCEPTION_TYPE(Base, KeyNotSupported)
DECLARE_EXCEPTION_TYPE(Base, OperationNotSupported)
DECLARE_EXCEPTION_TYPE(Base, WrongBackend)

} // namespace Exception
} // namespace Crypto
} // namespace CKM

