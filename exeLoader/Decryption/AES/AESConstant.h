#ifndef DECRYPTION_AESCONSTANT_H_INCLUDED
#define DECRYPTION_AESCONSTANT_H_INCLUDED

#include <windows.h>

namespace Decryption {
	extern const BYTE SBox[256];
	extern const BYTE InverseSBox[256];
	extern const UINT32 Rcon[11];
	extern const BYTE Multiply0x09[256];
	extern const BYTE Multiply0x0B[256];
	extern const BYTE Multiply0x0D[256];
	extern const BYTE Multiply0x0E[256];
}

#endif //DECRYPTION_AESCONSTANT_H_INCLUDED