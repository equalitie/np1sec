// advanced encryption standard
// author: karl malbrain, malbrain@yahoo.com

/*
This work, including the source code, documentation
and related data, is placed into the public domain.

The orginal author is Karl Malbrain.

THIS SOFTWARE IS PROVIDED AS-IS WITHOUT WARRANTY
OF ANY KIND, NOT EVEN THE IMPLIED WARRANTY OF
MERCHANTABILITY. THE AUTHOR OF THIS SOFTWARE,
ASSUMES _NO_ RESPONSIBILITY FOR ANY CONSEQUENCE
RESULTING FROM THE USE, MODIFICATION, OR
REDISTRIBUTION OF THIS SOFTWARE.
*/


#ifndef		AES_MALBRAIN
#define		AES_MALBRAIN


// AES only supports Nb=4
#define Nb 4			// number of columns in the state & expanded key

#define Nk 4			// number of columns in a key
#define Nr 10			// number of rounds in encryption


typedef unsigned char uchar;


void ExpandKey (uchar *key, uchar *expkey);
void Encrypt (uchar *in, uchar *expkey, uchar *out);
void Decrypt (uchar *in, uchar *expkey, uchar *out);


#endif		/* AES_MALBRAIN */

