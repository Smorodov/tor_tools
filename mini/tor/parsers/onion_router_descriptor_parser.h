#pragma once
#include <mini/string.h>
#include <mini/string_hash.h>
#include <mini/stack_buffer.h>
#include <mini/tor/onion_router.h>

namespace mini::tor
{

	struct onion_router_descriptor_parser
	{
		enum class document_location
		{
		    control_word,

		    onion_key,
		    onion_key_content,

		    signing_key,
		    signing_key_content,

		    ntor_onion_key,
		};

		enum control_word_type
		{
		    control_word_onion_key,
		    control_word_signing_key,

		    control_word_key_begin,
		    control_word_key_end,

		    control_word_ntor_onion_key,
		};

		using control_word_list = stack_buffer<string_hash, 5>;
		static constexpr control_word_list control_words = { {
				"onion-key",
				"signing-key",
				"-----BEGIN RSA PUBLIC KEY-----",
				"-----END RSA PUBLIC KEY-----",
				"ntor-onion-key",
			}
		};

		void
		parse(
		    onion_router* router,
		    const string_ref descriptor
		);
	};

}
