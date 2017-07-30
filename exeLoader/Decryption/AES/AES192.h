#ifndef AES192_DECRYPTION_H_INCLUDED
#define AES192_DECRYPTION_H_INCLUDED

#include "AESConstant.h"

namespace Decryption {
	namespace AES192 {
		void InverseCipher(BYTE srcBytes[16], const UINT32 srcExpandedKey[52]);
		void KeyExpansion(const BYTE srcKey[24], UINT32 dstExpandedKey[52]);
	}
}

#endif // AES192_DECRYPTION_H_INCLUDED
