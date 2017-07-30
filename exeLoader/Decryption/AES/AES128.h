#ifndef AES128_DECRYPTION_H_INCLUDED
#define AES128_DECRYPTION_H_INCLUDED

#include "AESConstant.h"

namespace Decryption {
	namespace AES128 {
		void InverseCipher(BYTE srcBytes[16], const UINT32 srcExpandedKey[44]);
		void KeyExpansion(const BYTE srcKey[16], UINT32 dstExpandedKey[44]);
	}
}

#endif // AES128_DECRYPTION_H_INCLUDED