#ifndef NEXUSMINER_NETWORK_TCP_CONNECTION_IMPL_HPP
#define NEXUSMINER_NETWORK_TCP_CONNECTION_IMPL_HPP

#include "asio/io_service.hpp"
#include "asio/write.hpp"
#include "network/connection.hpp"
#include "network/tcp/protocol_description.hpp"
#include "LLP/llp_logging.hpp"
#include <spdlog/spdlog.h>
#include <queue>
#include <memory>

namespace nexusminer {
namespace network {
namespace tcp {

template<typename ProtocolDescriptionType>
class Connection_impl
    : public Connection
    , public std::enable_shared_from_this<Connection_impl<ProtocolDescriptionType>>
{
    // protocol specific types
    using Protocol_description = ProtocolDescriptionType;
    using Protocol_socket = typename Protocol_description::Socket;
    using Protocol_endpoint = typename Protocol_description::Endpoint;

public:
    Connection_impl(std::shared_ptr<::asio::io_context> io_context,
                    Endpoint remote_endpoint, Endpoint local_endpoint, Connection::Handler handler);
    Connection_impl(std::shared_ptr<::asio::io_context> io_context,
                    std::shared_ptr<Protocol_socket> asio_socket, Endpoint remote_endpoint);

    // no copies
    Connection_impl(const Connection_impl&) = delete;
    Connection_impl& operator=(const Connection_impl&) = delete;
    // no moves
    Connection_impl(Connection_impl&&) = delete;
    Connection_impl& operator=(Connection_impl&&) = delete;

    // Connection interface
    Endpoint const& remote_endpoint() const override { return m_remote_endpoint; }
    Endpoint const& local_endpoint() const override { return m_local_endpoint; }
    void transmit(Shared_payload tx_buffer) override;
    void close() override;

    // interface towards socket
    Result::Code connect();
    void handle_accept(Connection::Handler connection_handler);

private:
    std::weak_ptr<Connection_impl<ProtocolDescriptionType>> get_weak_self();
    Result::Code initialise_socket();
    void transmit_trigger();
    void receive();
    void change(Result::Code code);
    void close_internal(Result::Code code);

    std::shared_ptr<::asio::io_context> m_io_context;
    std::shared_ptr<Protocol_socket> m_asio_socket;
    Endpoint m_remote_endpoint;
    Endpoint m_local_endpoint;
    std::queue<Shared_payload> m_tx_queue;
    Connection::Handler m_connection_handler;
    std::shared_ptr<spdlog::logger> m_logger;
};


template<typename ProtocolDescriptionType>
inline Connection_impl<ProtocolDescriptionType>::Connection_impl(
    std::shared_ptr<::asio::io_context> io_context, Endpoint remote_endpoint,
    Endpoint local_endpoint, Connection::Handler handler)
    : m_io_context{std::move(io_context)}
    , m_asio_socket{std::make_shared<Protocol_socket>(*m_io_context)}
    , m_remote_endpoint{std::move(remote_endpoint)}
    , m_local_endpoint{std::move(local_endpoint)}
    , m_tx_queue{}
    , m_connection_handler{std::move(handler)}
    , m_logger{spdlog::get("logger")}
{
}

template<typename ProtocolDescriptionType>
inline Connection_impl<ProtocolDescriptionType>::Connection_impl(
    std::shared_ptr<::asio::io_context> io_context,
    std::shared_ptr<Protocol_socket> asio_socket, Endpoint remote_endpoint)
    : m_io_context{std::move(io_context)}
    , m_asio_socket{std::move(asio_socket)}
    , m_remote_endpoint{std::move(remote_endpoint)}
    , m_local_endpoint{}     // will be set later, this constructor is called in accept/listen case
    , m_tx_queue{}
	, m_connection_handler{} // will be set later, this constructor is called in accept/listen case
    , m_logger{spdlog::get("logger")}
{
}

template<typename ProtocolDescriptionType>
inline std::weak_ptr<Connection_impl<ProtocolDescriptionType>>
Connection_impl<ProtocolDescriptionType>::get_weak_self()
{
    return this->shared_from_this();
}

template<typename ProtocolDescriptionType>
inline Result::Code
Connection_impl<ProtocolDescriptionType>::initialise_socket()
{
    asio::error_code error;
    this->m_asio_socket->open(get_endpoint_base<Protocol_endpoint>(m_local_endpoint).protocol(), error);
    if (error) 
	{
        return Result::error;
    }

    this->m_asio_socket->bind(get_endpoint_base<Protocol_endpoint>(m_local_endpoint), error);
    if (error)
	{
        m_asio_socket->close(error);
        return Result::error;
    }

    Protocol_description::update_port(m_asio_socket->local_endpoint(), m_local_endpoint);

    return Result::ok;
}


template<typename ProtocolDescriptionType>
inline Result::Code Connection_impl<ProtocolDescriptionType>::connect()
{
    if (initialise_socket() != Result::ok)
	{
        return Result::error;
    }

    std::weak_ptr<Connection_impl<ProtocolDescriptionType>> weak_self = this->shared_from_this();
    this->m_asio_socket->async_connect(get_endpoint_base<Protocol_endpoint>(m_remote_endpoint),
                                       [weak_self](::asio::error_code const& error)
	{
		auto self = weak_self.lock();
		if (self && self->m_connection_handler)
		{
            if (!error) 
            {
                self->change(Result::Code::connection_ok);
            }
            else 
            {
                self->change(Result::Code::connection_declined);
            }
		}
	});

    return Result::ok;
}

template<typename ProtocolDescriptionType>
inline void Connection_impl<ProtocolDescriptionType>::receive()
{
    m_asio_socket->async_receive(asio::null_buffers(), [weak_self = get_weak_self()](auto error, auto) 
	{        
        auto self = weak_self.lock();
        if (self && self->m_connection_handler) 
		{
            if (!error) 
            {
                // read length of received message;
                auto const length = self->m_asio_socket->available();
                if (length == 0)
                {
                    if (self->m_logger)
                    {
                        self->m_logger->warn("[LLP RECV] Connection closed by remote (EOF, no data available)");
                    }
                    self->change(Result::Code::connection_closed);
                    return;
                }

                Shared_payload receive_buffer = std::make_shared<std::vector<std::uint8_t>>(length);
                receive_buffer->resize(length);

                self->m_asio_socket->receive(asio::buffer(*receive_buffer, receive_buffer->size()), 0, error);
                if (!error)
                {
                    // Log received LLP packets
                    if (self->m_logger && receive_buffer && !receive_buffer->empty())
                    {
                        // Try to parse packet(s) from buffer for logging
                        std::size_t offset = 0;
                        while (offset < receive_buffer->size())
                        {
                            if (offset + 1 > receive_buffer->size()) break;
                            
                            std::uint8_t header = (*receive_buffer)[offset];
                            std::uint32_t pkt_length = 0;
                            
                            // Check if it's a data packet (has length field)
                            if (offset + 5 <= receive_buffer->size())
                            {
                                pkt_length = ((*receive_buffer)[offset + 1] << 24) + 
                                           ((*receive_buffer)[offset + 2] << 16) + 
                                           ((*receive_buffer)[offset + 3] << 8) + 
                                           (*receive_buffer)[offset + 4];
                            }
                            
                            // Create data payload for hex preview
                            network::Shared_payload data_payload;
                            if (offset + 5 < receive_buffer->size())
                            {
                                std::size_t data_end = std::min(offset + 5 + pkt_length, receive_buffer->size());
                                data_payload = std::make_shared<network::Payload>(
                                    receive_buffer->begin() + offset + 5, 
                                    receive_buffer->begin() + data_end);
                            }
                            
                            std::string hex_preview = format_llp_payload_hex(data_payload, 16);
                            if (!hex_preview.empty())
                            {
                                self->m_logger->info("[LLP RECV] header={} (0x{:02x}) {} length={} payload=[{}]", 
                                    static_cast<int>(header), header, get_llp_header_name(header), 
                                    pkt_length, hex_preview);
                            }
                            else
                            {
                                self->m_logger->info("[LLP RECV] header={} (0x{:02x}) {} length={}", 
                                    static_cast<int>(header), header, get_llp_header_name(header), pkt_length);
                            }
                            
                            // Move to next packet (header + 4 bytes length + data)
                            if (pkt_length > 0 && offset + 5 + pkt_length <= receive_buffer->size())
                            {
                                offset += 5 + pkt_length;
                            }
                            else if (pkt_length == 0)
                            {
                                // Request packet (no data)
                                offset += 1;
                            }
                            else
                            {
                                // Incomplete packet, stop logging
                                break;
                            }
                        }
                    }
                    
                    self->m_connection_handler(Result::receive_ok, std::move(receive_buffer));
                    self->receive();
                }
                else
                {
                    // established connection fails for any other reason
                    if (self->m_logger)
                    {
                        self->m_logger->error("[LLP RECV] Socket receive error: {}", error.message());
                    }
                    self->change(Result::Code::connection_aborted);
                }
            }
            else if ((error == ::asio::error::eof) || (error == ::asio::error::connection_reset))
            {
                // established connection closed by remote
                if (self->m_logger)
                {
                    self->m_logger->warn("[LLP RECV] Connection closed by remote: {}", error.message());
                }
                self->change(Result::Code::connection_closed);
            }
            else
            {
                // established connection fails for any other reason
                if (self->m_logger)
                {
                    self->m_logger->error("[LLP RECV] Connection error: {}", error.message());
                }
                self->change(Result::Code::connection_aborted);
            }
        }
    });
}

template<typename ProtocolDescriptionType>
inline void Connection_impl<ProtocolDescriptionType>::change(Result::Code code)
{
    if (code == Result::Code::connection_ok) 
    {
        m_connection_handler(code, Shared_payload{});
        receive();
    }
    else 
    {
        close_internal(code);
    }
}

template<typename ProtocolDescriptionType>
inline void Connection_impl<ProtocolDescriptionType>::handle_accept(Connection::Handler connection_handler)
{
    assert(connection_handler);
    m_connection_handler = std::move(connection_handler);
    m_local_endpoint = Endpoint(m_asio_socket->local_endpoint());
    change(Result::Code::connection_ok);
}


template<typename ProtocolDescriptionType>
void Connection_impl<ProtocolDescriptionType>::transmit(Shared_payload tx_buffer)
{
    // only for non closed connection
    if (m_connection_handler) 
    {
        m_tx_queue.emplace(tx_buffer);
        if (m_tx_queue.size() == 1) 
        {
            transmit_trigger();
        }
    }
}

template<typename ProtocolDescriptionType>
void Connection_impl<ProtocolDescriptionType>::transmit_trigger()
{
    auto const payload = m_tx_queue.front();
    
    // Log LLP packet send
    if (m_logger && payload && !payload->empty())
    {
        // Parse LLP packet header
        std::uint8_t header = (*payload)[0];
        std::uint32_t length = 0;
        
        // If payload has length field (data packets), extract it
        if (payload->size() >= 5)
        {
            length = ((*payload)[1] << 24) + ((*payload)[2] << 16) + 
                     ((*payload)[3] << 8) + (*payload)[4];
        }
        
        // Create a shared pointer to the data portion for hex formatting
        network::Shared_payload data_payload;
        if (payload->size() > 5)
        {
            data_payload = std::make_shared<network::Payload>(payload->begin() + 5, payload->end());
        }
        
        std::string hex_preview = format_llp_payload_hex(data_payload, 16);
        if (!hex_preview.empty())
        {
            m_logger->info("[LLP SEND] header={} (0x{:02x}) {} length={} payload=[{}]", 
                static_cast<int>(header), header, get_llp_header_name(header), length, hex_preview);
        }
        else
        {
            m_logger->info("[LLP SEND] header={} (0x{:02x}) {} length={}", 
                static_cast<int>(header), header, get_llp_header_name(header), length);
        }
    }
    
    ::asio::async_write(*m_asio_socket, ::asio::buffer(*payload, payload->size()),
        // don't forget to keep the payload until transmission has been completed!!!
        [weak_self = get_weak_self(), payload](auto, auto) 
        {
            auto self = weak_self.lock();
            if ((self != nullptr) && self->m_connection_handler) 
            {
                self->m_tx_queue.pop();
                if (!self->m_tx_queue.empty()) 
                {
                    self->transmit_trigger();
                }
            }
        });
}

template<typename ProtocolDescriptionType>
inline void Connection_impl<ProtocolDescriptionType>::close()
{
    close_internal(Result::Code::connection_closed);
}

template<typename ProtocolDescriptionType>
inline void Connection_impl<ProtocolDescriptionType>::close_internal(Result::Code code)
{
    if (m_connection_handler) 
    {
        if (m_asio_socket->is_open()) 
        {
            ::asio::error_code error;
            (void)m_asio_socket->shutdown(::asio::socket_base::shutdown_both, error);
            (void)m_asio_socket->close(error);
        }

        auto const connection_handler = std::move(m_connection_handler);
        m_connection_handler = nullptr;
        connection_handler(code, Shared_payload{});
    }
}

}
}
}

#endif