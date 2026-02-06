#include "MSQuicSocket.hpp"
#include "msquic.h"
#include "msquic_posix.h"
#include <thread>  // Required for std::this_thread::sleep_for
#include <chrono>  // Required for std::chrono::seconds, milliseconds, etc.
#define DEBUG 0
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API  
ServerStreamCallback( _In_ HQUIC Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event  )
{
    return ((MSQuicSocket*)Context)->ServerStream(Stream, Event); 
}
 
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ServerConnectionCallback( _In_ HQUIC Connection, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event )
{
    return ((MSQuicSocket*)Context)->ServerConnection(Connection, Event);
} 

// The server's callback for listener events from MsQuic.
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
ServerListenerCallback( _In_ HQUIC Listener, _In_opt_ void* Context, _Inout_ QUIC_LISTENER_EVENT* Event )
{
    return ((MSQuicSocket*)Context)->ServerListener(Event);
}

// The clients's callback for stream events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
ClientStreamCallback( _In_ HQUIC Stream, _In_opt_ void* Context, _Inout_ QUIC_STREAM_EVENT* Event  )
{
    return ((MSQuicSocket*)Context)->ClientStream(Stream, Event);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
ClientConnectionCallback( _In_ HQUIC Connection, _In_opt_ void* Context, _Inout_ QUIC_CONNECTION_EVENT* Event )
{
    return ((MSQuicSocket*)Context)->ClientConnection(Connection, Event);
}

// Allocates and sends some data over a QUIC stream.
void
MSQuicSocket::ServerSend( _In_ HQUIC Stream, const char * bytes, uint32_t length)
{

    /*QUIC_BUFFER* SendBuffer = new QUIC_BUFFER;
    SendBuffer->Buffer = (uint8_t*)bytes;
    SendBuffer->Length = length;*/

    auto* ctx = new SendCtx(bytes, length);

    if(DEBUG) printf("[strm][%p] Sending data...\n", Stream);

    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    QUIC_STATUS Status;
    if (QUIC_FAILED(Status = msQuic->StreamSend(Stream, &ctx->Buf, 1, QUIC_SEND_FLAG_FIN, ctx))) {
        if(DEBUG) printf("StreamSend failed, 0x%x!\n", Status);
        msQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
    }
}

// Runs the server side of the protocol.
int 
MSQuicSocket::CreateServerSocket(uint16_t UDPport)     
{
    test = 1;
    regConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    alpn = { sizeof("msquic") - 1, (uint8_t*)"msquic" };    
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    bool fail = false;
    // Open a handle to the library and get the API function table.
    if (QUIC_FAILED(Status = MsQuicOpen2(&msQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        fail = true;
    }

    // Create a registration for the app's connections.
    if (QUIC_FAILED(Status = msQuic->RegistrationOpen(&regConfig, &registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        fail = true;
    }
    
    if (fail) {
        if (msQuic != NULL) {
            if (configuration != NULL) 
                msQuic->ConfigurationClose(configuration); 
            if (registration != NULL) 
                msQuic->RegistrationClose(registration); // This will block until all outstanding child objects have been closed.
            MsQuicClose(msQuic);
        }
    }

    // Configures the address used for the listener to listen on all IP
    // addresses and the given UDP port.
    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, UDPport);

    //
    // Load the server configuration based on the command line.
    //
    if (!ServerLoadConfiguration()) {
        return 0;
    }

    //
    // Create/allocate a new listener object.
    //
    if (QUIC_FAILED(Status = msQuic->ListenerOpen(registration, ServerListenerCallback, this, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        if (Listener != NULL) {
            msQuic->ListenerClose(Listener);
        }
    }

    //
    // Starts listening for incoming connections.
    //
    if (QUIC_FAILED(Status = msQuic->ListenerStart(Listener, &alpn, 1, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        if (Listener != NULL) { 
            msQuic->ListenerClose(Listener);
        }
    }

    //
    // Continue listening for connections until the Enter key is pressed.
    //
    //sleep(1);
    return 1;
}

void
MSQuicSocket::ClientSend( _In_ HQUIC Connection, const char * bytes, uint32_t length  )
{
    QUIC_STATUS Status;
    HQUIC Stream = NULL;

    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //

    if (QUIC_FAILED(Status = msQuic->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, ClientStreamCallback, this, &Stream))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        if (QUIC_FAILED(Status)) {
            msQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        } 
    }

    if(DEBUG) printf("[strm][%p] Starting...\n", Stream);

    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    if (QUIC_FAILED(Status = msQuic->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamStart failed, 0x%x!\n", Status);
        msQuic->StreamClose(Stream);
        if (QUIC_FAILED(Status)) {
            msQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
    }
    /*QUIC_BUFFER* SendBuffer = new QUIC_BUFFER;
    SendBuffer->Buffer = (uint8_t*)bytes;
    SendBuffer->Length = length;*/

    auto* ctx = new SendCtx(bytes, length);

    //if(DEBUG) 
    printf("[strm][%p] Sending data...\n", Stream);

    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    if (QUIC_FAILED(Status = msQuic->StreamSend(Stream, &ctx->Buf, 1, QUIC_SEND_FLAG_FIN, ctx))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        if (QUIC_FAILED(Status)) {
            delete ctx;
            msQuic->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        }
    }
}

int 
MSQuicSocket::CreateClientSocket(std::string address, uint16_t UDPport, uint64_t IdleTimeout )     
{
    regConfig = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };
    alpn = { sizeof("msquic") - 1, (uint8_t*)"msquic" };
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    bool fail = false;
    //IdleTimeoutMs = IdleTimeout;
    // Open a handle to the library and get the API function table.
    if (QUIC_FAILED(Status = MsQuicOpen2(&msQuic))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        fail = true;
    }

    // Create a registration for the app's connections.
    if (QUIC_FAILED(Status = msQuic->RegistrationOpen(&regConfig, &registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        fail = true;
    }
    
    if (fail) {
        if (msQuic != NULL) {
            if (configuration != NULL) 
                msQuic->ConfigurationClose(configuration);
            if (registration != NULL) 
                msQuic->RegistrationClose(registration); // This will block until all outstanding child objects have been closed.
            MsQuicClose(msQuic);
        }
    }

    // Load the client configuration based on the "unsecure" command line option.
    if (!ClientLoadConfiguration()) {
        return 0;
    }

    HQUIC Connection = NULL;

    //
    // Allocate a new connection object.
    //
    if (QUIC_FAILED(Status = msQuic->ConnectionOpen(registration, ClientConnectionCallback, this, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        if (QUIC_FAILED(Status) && Connection != NULL) {
            msQuic->ConnectionClose(Connection);
        }
    }

    BOOLEAN value = TRUE;
    Status =
        msQuic->SetParam(
            Connection,
            QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
            sizeof(value),
            &value);
    //
    // Get the target / server name or IP from the command line.
    //
    const char* Target = address.c_str();
 
    if(DEBUG) printf("[conn][%p] Connecting...\n", Connection);

    //
    // Start the connection to the server.
    //
    if (QUIC_FAILED(Status = msQuic->ConnectionStart(Connection, configuration, QUIC_ADDRESS_FAMILY_UNSPEC, Target, UDPport))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        if (QUIC_FAILED(Status) && Connection != NULL) {
            msQuic->ConnectionClose(Connection);
        }
    }
    return 1;
}


// The server's callback for stream events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API 
MSQuicSocket::ServerStream( _In_ HQUIC Stream, _Inout_ QUIC_STREAM_EVENT* Event  )
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        //delete (QUIC_BUFFER*)Event->SEND_COMPLETE.ClientContext;
        delete (SendCtx*)Event->SEND_COMPLETE.ClientContext;
        if(DEBUG) printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:{
        //
        // Data was received from the peer on the stream.
        //
        if(DEBUG) 
            printf("[strm][%p] Data received\n", Stream);

        {
            std::lock_guard<std::mutex> lk(in_mtx);

            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                auto* b = Event->RECEIVE.Buffers[i].Buffer;
                auto n   = Event->RECEIVE.Buffers[i].Length;
                partialBytes[Stream].append((char*)b, (size_t)n);
            }
        }

        break;
    }
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        // 
        {
            std::lock_guard<std::mutex> lk(in_mtx);

            // Move the assembled message out of partialBytes into the inbound queue
            inbound.push_back(InboundMsg{ std::move(partialBytes[Stream]), Stream });


            // Reset partial buffer for this stream
            partialBytes[Stream].clear();
        }
        in_cv.notify_one();   
        if(DEBUG) 
            printf("[strm][%p] Peer shut down\n", Stream); 
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        {
            std::lock_guard<std::mutex> lk(in_mtx);

            // Move the assembled message out of partialBytes into the inbound queue
            inbound.push_back(InboundMsg{ std::move(partialBytes[Stream]), Stream });

            // Reset partial buffer for this stream
            partialBytes[Stream].clear();
        }
        in_cv.notify_one();   
        if(DEBUG) printf("[strm][%p] Peer aborted\n", Stream);
        msQuic->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        if(DEBUG) printf("[strm][%p] All done\n", Stream);
        try {
            if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
                msQuic->StreamClose(Stream);
            } 
        }
        catch (std::exception& e) {
            printf("Error closing stream\n"); 
        }
        break;        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for connection events from MsQuic.
//
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
MSQuicSocket::ServerConnection( _In_ HQUIC Connection, _Inout_ QUIC_CONNECTION_EVENT* Event )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        // The handshake has completed for the connection.
        if(DEBUG) printf("[conn][%p] Connected\n", Connection);
        msQuic->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            if(DEBUG) printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            if(DEBUG) printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        if(DEBUG) printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        try {
            if(DEBUG) printf("[conn][%p] All done\n", Connection);
            if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
                msQuic->ConnectionClose(Connection);
            }
            break;
        }
        catch (std::exception& e) {
            printf("Error closing stream\n");
        }          
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        if(DEBUG) printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        msQuic->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)ServerStreamCallback, this);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        if(DEBUG) printf("[conn][%p] Connection resumed!\n", Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}


// The server's callback for listener events from MsQuic.
_IRQL_requires_max_(PASSIVE_LEVEL)
_Function_class_(QUIC_LISTENER_CALLBACK)
QUIC_STATUS
QUIC_API
MSQuicSocket::ServerListener(_Inout_ QUIC_LISTENER_EVENT* Event )
{
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
    {
        BOOLEAN value = TRUE;

        msQuic->SetParam(
            Event->NEW_CONNECTION.Connection,
            QUIC_PARAM_CONN_DISABLE_1RTT_ENCRYPTION,
            sizeof(value),
            &value);

        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        msQuic->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)ServerConnectionCallback, this);
        Status = msQuic->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, configuration);
        break;
    }
    default:
        break;
    }
    return Status;
}

// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
BOOLEAN
MSQuicSocket::ServerLoadConfiguration()
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the server's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    //
    // Configures the server's resumption level to allow for resumption and
    // 0-RTT.
    //
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    //
    // Configures the server's settings to allow for the peer to open a single
    // bidirectional stream. By default connections are not configured to allow
    // any streams from the peer.
    //
    Settings.PeerBidiStreamCount = 1000;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;

    Config.CertFile.CertificateFile = "certificate.pem";
    Config.CertFile.PrivateKeyFile = "key.pem";
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Config.CredConfig.CertificateFile = &Config.CertFile;

    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = msQuic->ConfigurationOpen(registration, &alpn, 1, &Settings, sizeof(Settings), NULL, &configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    // Loads the TLS credential part of the configuration.
    if (QUIC_FAILED(Status = msQuic->ConfigurationLoadCredential(configuration, &Config.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

// The clients's callback for stream events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_STREAM_CALLBACK)
QUIC_STATUS
QUIC_API
MSQuicSocket::ClientStream( _In_ HQUIC Stream, _Inout_ QUIC_STREAM_EVENT* Event  )
{
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        //delete (QUIC_BUFFER*)Event->SEND_COMPLETE.ClientContext;
        delete (SendCtx*)Event->SEND_COMPLETE.ClientContext;

        //if(DEBUG) 
        printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:{
        //
        // Data was received from the peer on the stream.
        //

        {
            std::lock_guard<std::mutex> lk(in_mtx);

            for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; ++i) {
                auto* b = Event->RECEIVE.Buffers[i].Buffer;
                auto n   = Event->RECEIVE.Buffers[i].Length;
                partialBytes[Stream].append((char*)b, (size_t)n);
            }
        }

        const bool fin = (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0;
        if (fin) {
            printf("[strm][%p] Data recv\n", Stream);
        }
        break;
    }
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer gracefully shut down its send direction of the stream.
        //

        {
            std::lock_guard<std::mutex> lk(in_mtx);

            // Move the assembled message out of partialBytes into the inbound queue
            inbound.push_back(InboundMsg{ std::move(partialBytes[Stream]), Stream });

            // Reset partial buffer for this stream
            partialBytes[Stream].clear();
        }
        in_cv.notify_one();   
        if(DEBUG) 
        printf("[strm][%p] Peer aborted\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: 
        //
        // The peer aborted its send direction of the stream.
        //
        {
            std::lock_guard<std::mutex> lk(in_mtx);

            // Move the assembled message out of partialBytes into the inbound queue
            inbound.push_back(InboundMsg{ std::move(partialBytes[Stream]), Stream });

            // Reset partial buffer for this stream
            partialBytes[Stream].clear();
        }
        in_cv.notify_one();   
        if(DEBUG) 
            printf("[strm][%p] Peer shut down\n", Stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and MsQuic is done
        // with the stream. It can now be safely cleaned up.
        //
        
        if(DEBUG) printf("[strm][%p] All done\n", Stream);
        try {
            if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
                msQuic->StreamClose(Stream);
            }
        }
        catch (std::exception& e) {
            printf("Error closing stream\n");
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

// The clients's callback for connection events from MsQuic.
_IRQL_requires_max_(DISPATCH_LEVEL)
_Function_class_(QUIC_CONNECTION_CALLBACK)
QUIC_STATUS
QUIC_API
MSQuicSocket::ClientConnection( _In_ HQUIC Connection, _Inout_ QUIC_CONNECTION_EVENT* Event )
{
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        if(DEBUG) printf("[conn][%p] Connected\n", Connection);
        {
            std::lock_guard<std::mutex> lk(conn_mtx);
            connections.push_back(Connection);
        }
        conn_cv.notify_one();
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            if(DEBUG) printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            if(DEBUG) printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        if(DEBUG) printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        try {
            if(DEBUG) printf("[conn][%p] All done\n", Connection);
            if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
                msQuic->ConnectionClose(Connection);
            }
            break;
        }
        catch (std::exception& e) {
            printf("Error closing stream\n");
        }        
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        if(DEBUG) printf("[conn][%p] Resumption ticket received (%u bytes):\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        //for (uint32_t i = 0; i < Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength; i++) {
        //    printf("%.2X", (uint8_t)Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicket[i]);
        //}
        if(DEBUG) printf("\n");
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

// Helper function to load a client configuration.
BOOLEAN
MSQuicSocket::ClientLoadConfiguration()
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the client's idle timeout.
    //
    Settings.IdleTimeoutMs = IdleTimeoutMs;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    //
    // Configures a default client configuration, optionally disabling
    // server certificate validation.
    //
    QUIC_CREDENTIAL_CONFIG CredConfig;
    memset(&CredConfig, 0, sizeof(CredConfig));
    CredConfig.Type = QUIC_CREDENTIAL_TYPE_NONE;
    CredConfig.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //


    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = msQuic->ConfigurationOpen(registration, &alpn, 1, &Settings, sizeof(Settings), NULL, &configuration))) {
        printf("ConfigurationOpen Client failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(Status = msQuic->ConfigurationLoadCredential(configuration, &CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}
