#pragma once

#include <utility>

#include <ckm/ckm-raw-buffer.h>
#include <ckm/ckm-type.h>

#include <generic-backend/id.h>

namespace CKM {
namespace Crypto {

struct Token {
    RawBuffer buffer;
    Id        backendId;
    KeyType   keyType;
};

typedef std::pair<Token,Token> TokenPair;

} // namespace Crypto
} // namespace CKM

