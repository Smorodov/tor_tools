#include "onion_router.h"
#include "consensus.h"
#include "parsers/onion_router_descriptor_parser.h"

namespace mini::tor
{

	onion_router::onion_router(
	    consensus& consensus,
	    const string_ref name,
	    const string_ref ip,
	    uint16_t or_port,
	    uint16_t dir_port,
	    const byte_buffer_ref identity_fingerprint
	)
		: _consensus(consensus)
		, _name(name)
		, _ip(ip.get_buffer())
		, _or_port(or_port)
		, _dir_port(dir_port)
		, _identity_fingerprint(identity_fingerprint)
		, _flags(status_flag::none)
		, _onion_key()
		, _signing_key()
		, _ntor_onion_key()
		, _service_key()
		, _descriptor_fetched(false)
	{
	}

	consensus&
	onion_router::get_consensus(
	    void
	)
	{
		return _consensus;
	}

	string_ref
	onion_router::get_name(
	    void
	) const
	{
		return _name;
	}

	void
	onion_router::set_name(
	    const string_ref value
	)
	{
		_name = value;
	}


	net::ip_address
	onion_router::get_ip_address(
	    void
	) const
	{
		return _ip;
	}

	void
	onion_router::set_ip_address(
	    net::ip_address value
	)
	{
		_ip = value;
	}

	uint16_t
	onion_router::get_or_port(
	    void
	) const
	{
		return _or_port;
	}

	void
	onion_router::set_or_port(
	    uint16_t value
	)
	{
		_or_port = value;
	}

	uint16_t
	onion_router::get_dir_port(
	    void
	) const
	{
		return _dir_port;
	}

	void
	onion_router::set_dir_port(
	    uint16_t value
	)
	{
		_dir_port = value;
	}

	byte_buffer_ref
	onion_router::get_identity_fingerprint(
	    void
	) const
	{
		return _identity_fingerprint;
	}

	void
	onion_router::set_identity_fingerprint(
	    const byte_buffer_ref value
	)
	{
		_identity_fingerprint = value;
	}

	onion_router::status_flags
	onion_router::get_flags(
	    void
	) const
	{
		return _flags;
	}

	void
	onion_router::set_flags(
	    status_flags flags
	)
	{
		_flags = flags;
	}

	byte_buffer_ref
	onion_router::get_onion_key(
	    void
	)
	{
		if (!_descriptor_fetched)
		{
			fetch_descriptor();
		}
		return _onion_key;
	}

	void
	onion_router::set_onion_key(
	    const byte_buffer_ref value
	)
	{
		_onion_key = value;
	}

	byte_buffer_ref
	onion_router::get_signing_key(
	    void
	)
	{
		if (!_descriptor_fetched)
		{
			fetch_descriptor();
		}
		return _signing_key;
	}

	void
	onion_router::set_signing_key(
	    const byte_buffer_ref value
	)
	{
		_signing_key = value;
	}

	byte_buffer_ref
	onion_router::get_ntor_onion_key(
	    void
	)
	{
		if (!_descriptor_fetched)
		{
			fetch_descriptor();
		}
		return _ntor_onion_key;
	}

	void
	onion_router::set_ntor_onion_key(
	    const byte_buffer_ref value
	)
	{
		_ntor_onion_key = value;
	}

	byte_buffer_ref
	onion_router::get_service_key(
	    void
	)
	{
		return _service_key;
	}

	void
	onion_router::set_service_key(
	    const byte_buffer_ref value
	)
	{
		_service_key = value;
	}

	void
	onion_router::fetch_descriptor(
	    void
	)
	{
		onion_router_descriptor_parser parser;
		parser.parse(this, _consensus.get_onion_router_descriptor(_identity_fingerprint));
		_descriptor_fetched = true;
	}

}
