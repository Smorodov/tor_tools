#include "hidden_service.h"

#include <mini/algorithm.h>
#include <mini/logger.h>
#include <mini/crypto/base16.h>
#include <mini/crypto/base32.h>
#include <mini/crypto/random.h>
#include <mini/crypto/sha1.h>
#include <mini/io/memory_stream.h>
#include <mini/io/stream_reader.h>
#include <mini/io/stream_wrapper.h>
#include <mini/tor/parsers/hidden_service_descriptor_parser.h>
#include <mini/net/http.h>

namespace mini::tor
{

	hidden_service::hidden_service(
	    circuit* rendezvous_circuit,
	    const string_ref onion
	)
		: _rendezvous_circuit(rendezvous_circuit)
		, _socket(rendezvous_circuit->get_tor_socket())
		, _consensus(rendezvous_circuit->get_tor_socket().get_onion_router()->get_consensus())
		, _onion(onion)
		, _permanent_id(crypto::base32::decode(_onion))
	{
		mini_debug("hidden_service() [%s.onion]", onion.get_buffer());
	}

	bool
	hidden_service::connect(
	    void
	)
	{
		find_responsible_directories();
		if (_responsible_directory_list.is_empty() == false)
		{
			//
			// create rendezvous cookie.
			//
			crypto::random_device.get_random_bytes(_rendezvous_cookie);
			//
			// establish rendezvous.
			//
			_rendezvous_circuit->rendezvous_establish(_rendezvous_cookie);
			if (_rendezvous_circuit->is_rendezvous_established())
			{
				onion_router_list::size_type responsible_directory_index = 0;
				while ((responsible_directory_index = fetch_hidden_service_descriptor(responsible_directory_index)) != onion_router_list::not_found)
				{
					introduce();
					if (_rendezvous_circuit->is_rendezvous_completed())
					{
						return true;
					}
				}
			}
		}
		return false;
	}

	byte_buffer
	hidden_service::get_secret_id(
	    replica_type replica
	)
	{
		byte_type permanent_id_byte = _permanent_id[0];
		//
		// rend-spec.txt
		// 1.3.
		//
		// "time-period" changes periodically as a function of time and
		// "permanent-id". The current value for "time-period" can be calculated
		// using the following formula:
		//
		//   time-period = (current-time + permanent-id-byte * 86400 / 256)
		//                   / 86400
		//
		uint32_t time_period = (time::now().to_timestamp() + (permanent_id_byte * 86400 / 256)) / 86400;
		stack_byte_buffer<5> secret_bytes;
		io::memory_stream secret_stream(secret_bytes);
		io::stream_wrapper secret_buffer(secret_stream, endianness::big_endian);
		secret_buffer.write(time_period);
		secret_buffer.write(replica);
		return crypto::sha1::compute(secret_bytes);
	}

	byte_buffer
	hidden_service::get_descriptor_id(
	    replica_type replica
	)
	{
		auto secret_id = get_secret_id(replica);
		byte_buffer descriptor_id_bytes =
		{
			_permanent_id,
			secret_id
		};
		return crypto::sha1::compute(descriptor_id_bytes);
	}

	void
	hidden_service::find_responsible_directories(
	    void
	)
	{
		//
		// rend-spec.txt
		// 1.4.
		// At any time, there are 6 hidden service directories responsible for
		// keeping replicas of a descriptor; they consist of 2 sets of 3 hidden
		// service directories with consecutive onion IDs. Bob's OP learns about
		// the complete list of hidden service directories by filtering the
		// consensus status document received from the directory authorities. A
		// hidden service directory is deemed responsible for a descriptor ID if
		// it has the HSDir flag and its identity digest is one of the first three
		// identity digests of HSDir relays following the descriptor ID in a
		// circular list. A hidden service directory will only accept a descriptor
		// whose timestamp is no more than three days before or one day after the
		// current time according to the directory's clock.
		//
		_responsible_directory_list.clear();
		auto directory_list = _consensus.get_onion_routers_by_criteria(
		{
			{}, {}, {},
			onion_router::status_flag::hsdir
		});
		//
		// search for the 2 sets of 3 hidden service directories.
		//
		for (replica_type replica = 0; replica < 2; replica++)
		{
			auto descriptor_id = get_descriptor_id(replica);
			auto directory_list_iterator = algorithm::lower_bound(
			                                   directory_list.begin(),
			                                   directory_list.end(),
			                                   descriptor_id,
			                                   [](onion_router* lhs, const byte_buffer_ref rhs) -> bool
			{
				return lhs->get_identity_fingerprint().compare(rhs) < 0;
			}
			                               );
			auto index = algorithm::distance(directory_list.begin(), directory_list_iterator) + 1;
			for (size_type i = 0; i < 3; i++)
			{
				_responsible_directory_list.add(directory_list[(index + i) % directory_list.get_size()]);
			}
		}
	}

	onion_router_list::size_type
	hidden_service::fetch_hidden_service_descriptor(
	    onion_router_list::size_type responsible_directory_index
	)
	{
		for (
		    onion_router_list::size_type i = responsible_directory_index;
		    i < _responsible_directory_list.get_size();
		    i++
		)
		{
			onion_router* responsible_directory = _responsible_directory_list[i];
			//
			// create new circuit and extend it with responsible directory.
			//
			mini_info(
			    "\tCreating circuit for hidden service (try #%u), connecting to '%s' (%s:%u)",
			    (uint32_t)(i + 1),
			    _socket.get_onion_router()->get_name().get_buffer(),
			    _socket.get_onion_router()->get_ip_address().to_string().get_buffer(),
			    _socket.get_onion_router()->get_or_port());
			mini_info("\tConnected...");
			ptr<circuit> directory_circuit = _socket.create_circuit();
			if (!directory_circuit)
			{
				//
				// either tor socket is destroyed
				// or we couldn't create circuit with the first
				// onion router. try it again anyway.
				// but if the socket is destroyed, we're out of luck.
				//
				continue;
			}
			mini_info(
			    "\tExtending circuit for hidden service, connecting to responsible directory '%s' (%s:%u)",
			    responsible_directory->get_name().get_buffer(),
			    responsible_directory->get_ip_address().to_string().get_buffer(),
			    responsible_directory->get_or_port());
			directory_circuit->extend(responsible_directory);
			if (!directory_circuit->is_ready())
			{
				mini_warning("\tError while extending the directory circuit");
				continue;
			}
			//
			// circuit must have exactly 2 nodes now.
			//
			mini_assert(directory_circuit->get_circuit_node_list_size() == 2);
			mini_info("\tExtended...");
			replica_type replica = i >= 3;
			//
			// create the directory stream on the directory circuit.
			//
			ptr<tor_stream> directory_stream = directory_circuit->create_dir_stream();
			if (!directory_stream)
			{
				mini_warning("\tError while establishing the directory stream");
				continue;
			}
			//
			// request the hidden service descriptor.
			//
			const string descriptor_path = string::format(
			                                   "/tor/rendezvous2/%s",
			                                   crypto::base32::encode(get_descriptor_id(replica)).get_buffer());
			mini_debug(
			    "hidden_service::fetch_hidden_service_descriptor() [path: %s]",
			    descriptor_path.get_buffer());
			mini_info("\tSending request for hidden service descriptor...");
			const string hidden_service_descriptor =
			    net::http::client::get(
			        responsible_directory->get_ip_address().to_string(),
			        responsible_directory->get_dir_port(),
			        descriptor_path,
			        *directory_stream);
			mini_info("\tHidden service descriptor received...");
			//
			// parse hidden service descriptor.
			//
			if (!hidden_service_descriptor.is_empty() &&
			        !hidden_service_descriptor.contains("404 Not found"))
			{
				mini_info("\tHidden service descriptor is valid...");
				hidden_service_descriptor_parser parser;
				parser.parse(_consensus, hidden_service_descriptor);
				mini_assert(!parser.introduction_point_list.is_empty());
				if (!parser.introduction_point_list.is_empty())
				{
					_introduction_point_list = std::move(parser.introduction_point_list);
				}
				else
				{
					mini_warning("\tHidden service descriptor contains no introduction points...");
				}
				return i;
			}
			else
			{
				mini_warning("\tHidden service descriptor is invalid...");
			}
		}
		return onion_router_list::not_found;
	}

	void
	hidden_service::introduce(
	    void
	)
	{
for (onion_router* introduction_point : _introduction_point_list)
		{
			mini_info(
			    "\tCreating circuit for hidden service introduce, connecting to '%s' (%s:%u)",
			    _socket.get_onion_router()->get_name().get_buffer(),
			    _socket.get_onion_router()->get_ip_address().to_string().get_buffer(),
			    _socket.get_onion_router()->get_or_port());
			ptr<circuit> introduce_circuit = _socket.create_circuit();
			if (!introduce_circuit)
			{
				//
				// either tor socket is destroyed
				// or we couldn't create circuit with the first
				// onion router. try it again anyway.
				// but if the socket is destroyed, we're out of luck.
				//
				continue;
			}
			mini_info("\tConnected...");
			mini_info(
			    "\tExtending circuit to introduction point '%s' (%s:%u)",
			    introduction_point->get_name().get_buffer(),
			    introduction_point->get_ip_address().to_string().get_buffer(),
			    introduction_point->get_or_port());
			introduce_circuit->extend(introduction_point);
			if (!introduce_circuit->is_ready())
			{
				mini_warning("\tError while extending the introduce circuit");
				continue;
			}
			//
			// circuit must have exactly 2 nodes now.
			//
			mini_assert(introduce_circuit->get_circuit_node_list_size() == 2);
			mini_info("\tExtended...");
			mini_info("\tSending introduce...");
			introduce_circuit->rendezvous_introduce(_rendezvous_circuit, _rendezvous_cookie);
			if (introduce_circuit->get_state() == circuit::state::rendezvous_introduced)
			{
				mini_info("\tIntroduced successfully...");
				break;
			}
			else
			{
				mini_warning("\tIntroduce failed...");
			}
		}
	}

}
