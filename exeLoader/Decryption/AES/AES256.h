#ifndef AES256_DECRYPTION_H_INCLUDED
#define AES256_DECRYPTION_H_INCLUDED

#include "AESConstant.h"

namespace Decryption {
	namespace AES256 {
		void InverseCipher(BYTE srcBytes[16], const UINT32 srcExpandedKey[60]);
		void KeyExpansion(const BYTE srcKey[32], UINT32 dstExpandedKey[60]);
	}
}

#endif // AES256_DECRYPTION_H_INCLUDED
