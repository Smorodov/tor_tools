#pragma once
#include "tor_socket.h"
#include "tor_stream.h"
#include "relay_cell.h"

#include <mini/threading/locked_value.h>

namespace mini::tor
{

	using circuit_node_list = collections::list<ptr<circuit_node>>;

	class circuit_node;

	class circuit
	{
		public:
			circuit(
			    tor_socket& tor_socket
			);

			~circuit(
			    void
			);

			tor_socket&
			get_tor_socket(
			    void
			);

			circuit_id_type
			get_circuit_id(
			    void
			) const;

			const circuit_node_list&
			get_circuit_node_list(
			    void
			) const;

			size_type
			get_circuit_node_list_size(
			    void
			) const;

			circuit_node*
			get_final_circuit_node(
			    void
			);

			tor_stream*
			create_stream(
			    const string_ref host,
			    uint16_t port
			);

			tor_stream*
			create_onion_stream(
			    const string_ref onion,
			    uint16_t port
			);

			tor_stream*
			create_dir_stream(
			    void
			);

			void
			create(
			    onion_router* first_onion_router,
			    handshake_type handshake = preferred_handshake_type
			);

			void
			extend(
			    onion_router* next_onion_router,
			    handshake_type handshake = preferred_handshake_type
			);

			void
			destroy(
			    void
			);

			bool
			is_destroyed(
			    void
			) const;

			bool
			is_ready(
			    void
			) const;

			tor_stream*
			get_stream_by_id(
			    tor_stream_id_type stream_id
			);

		private:
			friend class tor_stream;
			friend class tor_socket;
			friend class hidden_service;

			using tor_stream_map = collections::pair_list<tor_stream_id_type, tor_stream*>;

			enum class state
			{
			    none,
			    creating,
			    extending,
			    connecting,
			    ready,
			    destroyed,

			    rendezvous_establishing,
			    rendezvous_established,
			    rendezvous_introducing,
			    rendezvous_introduced,
			    rendezvous_completing,
			    rendezvous_completed,
			};

			void
			create_tap(
			    onion_router* first_onion_router
			);

			void
			create_ntor(
			    onion_router* first_onion_router
			);

			void
			extend_tap(
			    onion_router* next_onion_router
			);

			void
			extend_ntor(
			    onion_router* next_onion_router
			);

			void
			close_streams(
			    void
			);

			circuit_node*
			create_circuit_node(
			    onion_router* router,
			    circuit_node_type type = circuit_node_type::normal
			);

			void
			rendezvous_establish(
			    const byte_buffer_ref rendezvous_cookie
			);

			bool
			is_rendezvous_established(
			    void
			) const;

			void
			rendezvous_introduce(
			    circuit* rendezvous_circuit,
			    const byte_buffer_ref rendezvous_cookie
			);

			bool
			is_rendezvous_introduced(
			    void
			) const;

			bool
			is_rendezvous_completed(
			    void
			) const;

			cell&
			encrypt(
			    relay_cell& cell
			);

			cell&
			encrypt(
			    relay_cell&& cell
			);

			relay_cell
			decrypt(
			    cell& cell
			);

			void
			send_cell(
			    const cell& cell
			);

			void
			send_destroy_cell(
			    void
			);

			void
			send_relay_cell(
			    tor_stream_id_type stream_id,
			    cell_command relay_command,
			    const byte_buffer_ref payload = byte_buffer_ref(),
			    cell_command cell_command = cell_command::relay,
			    circuit_node* node = nullptr
			);

			void
			send_relay_data_cell(
			    tor_stream* stream,
			    const byte_buffer_ref buffer
			);

			void
			send_relay_end_cell(
			    tor_stream* stream
			);

			void
			send_relay_sendme_cell(
			    tor_stream* stream
			);

			void
			handle_cell(
			    cell& cell
			);

			void
			handle_created_cell(
			    cell& cell
			);

			void
			handle_created2_cell(
			    cell& cell
			);

			void
			handle_destroyed_cell(
			    cell& cell
			);

			void
			handle_relay_extended_cell(
			    relay_cell& cell
			);

			void
			handle_relay_extended2_cell(
			    relay_cell& cell
			);

			void
			handle_relay_data_cell(
			    relay_cell& cell
			);

			void
			handle_relay_sendme_cell(
			    relay_cell& cell
			);

			void
			handle_relay_connected_cell(
			    relay_cell& cell
			);

			void
			handle_relay_truncated_cell(
			    relay_cell& cell
			);

			void
			handle_relay_end_cell(
			    relay_cell& cell
			);

			circuit_id_type
			get_next_circuit_id(
			    void
			);

			tor_stream_id_type
			get_next_stream_id(
			    void
			);

			state
			get_state(
			    void
			) const;

			void
			set_state(
			    state new_state
			);

			threading::wait_result
			wait_for_state(
			    state desired_state,
			    timeout_type timeout = 30000
			);

			tor_socket& _tor_socket;
			circuit_id_type _circuit_id;

			threading::locked_value<state> _state;

			tor_stream_map _stream_map;

			circuit_node* _extend_node = nullptr;
			circuit_node_list _node_list;
	};

}
