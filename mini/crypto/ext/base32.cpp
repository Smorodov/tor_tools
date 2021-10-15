#include "base32.h"

#include <mini/stack_buffer.h>

namespace mini::crypto::ext
{

	//
	// RFC 4648 alphabet.
	//

	//
	// functions.
	//

	static size_type
	get_encode_length(
	    size_type bytes
	)
	{
		size_type bits   = bytes * 8;
		size_type length = bits  / 5;
		if ((bits % 5) > 0)
		{
			length++;
		}
		return length;
	}

	static size_type
	get_decode_length(
	    size_type bytes
	)
	{
		size_type bits   = bytes * 5;
		size_type length = bits  / 8;
		return length;
	}

	static void
	encode_chunk(
	    const byte_type input[5],
	    byte_type output[8]
	)
	{
		//
		// pack 5 bytes
		//
		uint64_t buffer = 0;
		for (int i = 0; i < 5; i++)
		{
			buffer = (buffer << 8) | input[i];
		}
		//
		// output 8 bytes
		//
		for (int i = 7; i >= 0; i--)
		{
			buffer <<= (24 + (7 - i) * 5);
			buffer >>= (24 + (7 - i) * 5);
			byte_type c = (byte_type)(buffer >> (i * 5));
			output[7 - i] = c + (c < 0x1a ? 'a' : ('2' - 0x1a));
		}
	}

	static void
	decode_chunk(
	    const byte_type input[8],
	    byte_type output[5]
	)
	{
		//
		// pack 8 bytes
		//
		uint64_t buffer = 0;
		for (int i = 0; i < 8; i++)
		{
			buffer = (buffer << 5) | (byte_type)(input[i] - (input[i] >= 'a' ? 'a' : ('2' - 0x1a)));
		}
		//
		// output 5 bytes
		//
		for (int j = 4; j >= 0; j--)
		{
			output[4 - j] = (byte_type)(buffer >> (j * 8));
		}
	}

	string
	base32::encode(
	    const byte_buffer_ref input
	)
	{
		string output(get_encode_length(input.get_size()));
		//
		// get quotient & remainder.
		//
		size_type q = input.get_size() / 5;
		size_type r = input.get_size() % 5;
		byte_type out_chunk_buffer[8];
		for (size_type j = 0; j < q; j++)
		{
			encode_chunk(&input[j * 5], &out_chunk_buffer[0]);
			memmove(&output[j * 8], &out_chunk_buffer[0], sizeof(byte_type) * 8);
		}
		byte_type out_padding_buffer[5] = { 0 };
		for (size_type i = 0; i < r; i++)
		{
			out_padding_buffer[i] = input[input.get_size() - r + i];
		}
		encode_chunk(&out_padding_buffer[0], &out_chunk_buffer[0]);
		memmove(&output[q * 8], &out_chunk_buffer[0], sizeof(byte_type) * get_encode_length(r));
		return output;
	}

	byte_buffer
	base32::decode(
	    const string_ref input
	)
	{
		byte_buffer output(get_decode_length(input.get_size()));
		//
		// get quotient & remainder.
		//
		size_type q = input.get_size() / 8;
		size_type r = input.get_size() % 8;
		byte_type out_chunk_buffer[5];
		for (size_type j = 0; j < q; j++)
		{
			decode_chunk((byte_type*)&input[j * 8], &out_chunk_buffer[0]);
			memmove(&output[j * 5], &out_chunk_buffer[0], sizeof(byte_type) * 5);
		}
		byte_type out_padding_buffer[8] = { 0 };
		for (size_type i = 0; i < r; i++)
		{
			out_padding_buffer[i] = input[input.get_size() - r + i];
		}
		decode_chunk(&out_padding_buffer[0], &out_chunk_buffer[0]);
		memmove(&output[q * 5], &out_chunk_buffer[0], sizeof(byte_type) * get_decode_length(r));
		return output;
	}

}
