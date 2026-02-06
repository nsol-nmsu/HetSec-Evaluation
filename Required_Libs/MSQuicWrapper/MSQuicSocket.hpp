#ifndef MSQUIC_H
#define MSQUIC_H

#define QUIC_API_ENABLE_INSECURE_FEATURES
#include <stdio.h>
#include <stdlib.h>
#include "msquic.h"
#include <vector>
#include <unordered_map>
#include <iostream>
#include <mutex>
#include <condition_variable>
#include <deque>


struct InboundMsg {
    std::string data;
    HQUIC stream;
};

struct SendCtx {
    QUIC_BUFFER Buf;
    std::vector<uint8_t> Data;
    SendCtx(const char* p, uint32_t n) : Data(p, p + n) {
        Buf.Buffer = Data.data();
        Buf.Length = n;
    }
};

class MSQuicSocket{
public:
    MSQuicSocket(){};
    ~MSQuicSocket(){};

    void
    ServerSend( _In_ HQUIC Stream, const char * bytes, uint32_t length );

    int 
    CreateServerSocket(uint16_t UDPport);

    void
    ClientSend( _In_ HQUIC Connection, const char * bytes, uint32_t length );

    int 
    CreateClientSocket(std::string address, uint16_t UDPport, uint64_t IdleTimeout);

    
    typedef struct QUIC_CREDENTIAL_CONFIG_HELPER {
        QUIC_CREDENTIAL_CONFIG CredConfig;
        union {
            QUIC_CERTIFICATE_HASH CertHash;
            QUIC_CERTIFICATE_HASH_STORE CertHashStore;
            QUIC_CERTIFICATE_FILE CertFile;
            QUIC_CERTIFICATE_FILE_PROTECTED CertFileProtected;
        };
    } QUIC_CREDENTIAL_CONFIG_HELPER;



    #ifndef UNREFERENCED_PARAMETER
    #define UNREFERENCED_PARAMETER(P) (void)(P)
    #endif

    // Helper function to convert a hex character to its decimal value.
    uint8_t
    DecodeHexChar( _In_ char c )
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return 10 + c - 'A';
        if (c >= 'a' && c <= 'f') return 10 + c - 'a';
        return 0;
    }


    // Helper function to convert a string of hex characters to a byte buffer.
    uint32_t
    DecodeHexBuffer( _In_z_ const char* HexBuffer, _In_ uint32_t OutBufferLen, _Out_writes_to_(OutBufferLen, return) uint8_t* OutBuffer )
    {
        uint32_t HexBufferLen = (uint32_t)strlen(HexBuffer) / 2;
        if (HexBufferLen > OutBufferLen) {
            return 0;
        }

        for (uint32_t i = 0; i < HexBufferLen; i++) {
            OutBuffer[i] =
                (DecodeHexChar(HexBuffer[i * 2]) << 4) |
                DecodeHexChar(HexBuffer[i * 2 + 1]);
        }

        return HexBufferLen;
    }


    // The server's callback for stream events from MsQuic.
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK)
    QUIC_STATUS
    QUIC_API 
    ServerStream( _In_ HQUIC Stream, _Inout_ QUIC_STREAM_EVENT* Event  );

    //
    // The server's callback for connection events from MsQuic.
    //
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ServerConnection( _In_ HQUIC Connection, _Inout_ QUIC_CONNECTION_EVENT* Event );

    // The server's callback for listener events from MsQuic.
    _IRQL_requires_max_(PASSIVE_LEVEL)
    _Function_class_(QUIC_LISTENER_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ServerListener(_Inout_ QUIC_LISTENER_EVENT* Event );

    // Helper function to load a server configuration. Uses the command line
    // arguments to load the credential part of the configuration.
    BOOLEAN
    ServerLoadConfiguration();

    // The clients's callback for stream events from MsQuic.
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_STREAM_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ClientStream( _In_ HQUIC Stream, _Inout_ QUIC_STREAM_EVENT* Event  );

    // The clients's callback for connection events from MsQuic.
    _IRQL_requires_max_(DISPATCH_LEVEL)
    _Function_class_(QUIC_CONNECTION_CALLBACK)
    QUIC_STATUS
    QUIC_API
    ClientConnection( _In_ HQUIC Connection, _Inout_ QUIC_CONNECTION_EVENT* Event );

    // Helper function to load a client configuration.
    BOOLEAN
    ClientLoadConfiguration();

    /*std::string
    getData(){
        while(recievedBytes.size() == 0){
          sleep(0.000001);
        }
        std::cout<<"Data Buffer before: "<< recievedBytes.size()<<std::endl;

        std::string s = recievedBytes.back();
        recievedBytes.pop_back();
        std::cout<<"Data Buffer after: "<< recievedBytes.size()<<std::endl;
        return s;
    };*/

    InboundMsg getMsgBlocking() {
        std::unique_lock<std::mutex> lk(in_mtx);
        in_cv.wait(lk, [&]{ return !inbound.empty(); });

        InboundMsg msg = std::move(inbound.front());
        inbound.pop_front();
        return msg;
    }

    bool tryGetMsg(InboundMsg& out) {
        std::lock_guard<std::mutex> lk(in_mtx);
        if (inbound.empty()) return false;
        out = std::move(inbound.front());
        inbound.pop_front();
        return true;
    }
    /*std::string
    getDataNow(){
        if(recievedBytes.size() == 0){
          return "";
        }
        std::cout<<"Data Buffer Now: "<< recievedBytes.size()<<std::endl;
        std::string s = recievedBytes.back();
        recievedBytes.pop_back();
        std::cout<<"Data Buffer Now: "<< recievedBytes.size()<< "  "<< s.length()<<  std::endl;
        return s;
    };*/

    /*void
    getSocket(){
        currentStream = recievedStreams.back();
        currentStreams[currentStreamID] = currentStream;
        currentStreamID++;
        recievedStreams.pop_back();
    };*/

    int
    checkConnection(){
        std::unique_lock<std::mutex> lk(conn_mtx);
        conn_cv.wait(lk, [&]{ return !connections.empty(); });
        return 1;
    };

private:        
    // This sets a name for the app and configures the execution profile.
    QUIC_REGISTRATION_CONFIG regConfig;
    // The protocol name used in the Application Layer Protocol Negotiation (ALPN).
    QUIC_BUFFER alpn;
    // The QUIC API/function table, contains all the functions called by the app.
    const QUIC_API_TABLE* msQuic;
    // The QUIC handle to the registration object. Represents the execution context for MSQuic.
    HQUIC registration;
    // The QUIC handle to the configuration object. This object abstracts the connection configuration. 
    HQUIC configuration;
    int pendingData;

    HQUIC Listener = NULL;

    // The UDP port used by the server side of the protocol.
    uint16_t UdpPort = 4567;
    // The default idle timeout period (1 second) used for the protocol.
    uint64_t IdleTimeoutMs = 100000;
    // The length of buffer sent over the streams in the protocol.
    uint32_t SendBufferLength = 100;

    std::mutex in_mtx;
    std::condition_variable in_cv;
    std::deque<InboundMsg> inbound;

    std::mutex conn_mtx;
    std::condition_variable conn_cv;
public:
    std::unordered_map<HQUIC, std::string> partialBytes;
    HQUIC currentStream = NULL;
    std::vector<HQUIC> connections;
    std::unordered_map<int, HQUIC> currentStreams;
    int currentStreamID = 0;
    int test;

};
#endif