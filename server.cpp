#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <windows.h>
#include <wincrypt.h>
#include <winsock2.h>
#include <cstdint>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")

using namespace std;

#ifndef CALG_AES_256
#define CALG_AES_256 0x00006610
#endif

#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif


// =========================================
// RECEIVE ALL
// =========================================

bool recvAll(
    SOCKET socket,
    char* buffer,
    int totalBytes)
{
    int receivedBytes = 0;

    while (receivedBytes < totalBytes)
    {
        int result = recv(
            socket,
            buffer + receivedBytes,
            totalBytes - receivedBytes,
            0
        );

        if (result <= 0)
        {
            return false;
        }

        receivedBytes += result;
    }

    return true;
}


// =========================================
// RECEIVE UINT64
// =========================================

bool recvUint64(
    SOCKET socket,
    uint64_t& value)
{
    uint32_t high;
    uint32_t low;

    if (!recvAll(
            socket,
            (char*)&high,
            sizeof(high)))
    {
        return false;
    }

    if (!recvAll(
            socket,
            (char*)&low,
            sizeof(low)))
    {
        return false;
    }

    high = ntohl(high);
    low = ntohl(low);

    value =
        ((uint64_t)high << 32) |
        low;

    return true;
}


// =========================================
// SEND ALL
// =========================================

bool sendAll(
    SOCKET socket,
    const char* buffer,
    int totalBytes)
{
    int sentBytes = 0;

    while (sentBytes < totalBytes)
    {
        int result = send(
            socket,
            buffer + sentBytes,
            totalBytes - sentBytes,
            0
        );

        if (result == SOCKET_ERROR)
        {
            return false;
        }

        sentBytes += result;
    }

    return true;
}


// =========================================
// RECEIVE STRING
// =========================================

bool receiveString(
    SOCKET socket,
    string& text)
{
    uint32_t lengthNetwork;

    if (!recvAll(
            socket,
            (char*)&lengthNetwork,
            sizeof(lengthNetwork)))
    {
        return false;
    }

    uint32_t length =
        ntohl(lengthNetwork);

    if (length > 1000)
    {
        return false;
    }

    char buffer[1001];

    if (!recvAll(
            socket,
            buffer,
            length))
    {
        return false;
    }

    buffer[length] = '\0';

    text = buffer;

    return true;
}


// =========================================
// SEND STRING
// =========================================

bool sendString(
    SOCKET socket,
    const string& text)
{
    uint32_t length =
        (uint32_t)text.length();

    uint32_t lengthNetwork =
        htonl(length);

    if (!sendAll(
            socket,
            (char*)&lengthNetwork,
            sizeof(lengthNetwork)))
    {
        return false;
    }

    if (!sendAll(
            socket,
            text.c_str(),
            length))
    {
        return false;
    }

    return true;
}


// =========================================
// CALCULATE SHA-256 OF STRING
// =========================================

bool calculateStringSHA256(
    const string& text,
    string& hashResult)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(
            &hProv,
            NULL,
            NULL,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT))
    {
        return false;
    }

    if (!CryptCreateHash(
            hProv,
            CALG_SHA_256,
            0,
            0,
            &hHash))
    {
        CryptReleaseContext(
            hProv,
            0);

        return false;
    }

    if (!CryptHashData(
            hHash,
            (BYTE*)text.c_str(),
            (DWORD)text.length(),
            0))
    {
        CryptDestroyHash(hHash);

        CryptReleaseContext(
            hProv,
            0);

        return false;
    }

    BYTE hash[32];

    DWORD hashSize =
        sizeof(hash);

    if (!CryptGetHashParam(
            hHash,
            HP_HASHVAL,
            hash,
            &hashSize,
            0))
    {
        CryptDestroyHash(hHash);

        CryptReleaseContext(
            hProv,
            0);

        return false;
    }

    stringstream ss;

    for (DWORD i = 0;
         i < hashSize;
         i++)
    {
        ss << hex
           << setw(2)
           << setfill('0')
           << (int)hash[i];
    }

    hashResult =
        ss.str();

    CryptDestroyHash(hHash);

    CryptReleaseContext(
        hProv,
        0);

    return true;
}


// =========================================
// GENERATE RANDOM CHALLENGE
// =========================================

bool generateChallenge(
    BYTE challenge[32])
{
    HCRYPTPROV hProv = 0;

    if (!CryptAcquireContext(
            &hProv,
            NULL,
            NULL,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT))
    {
        return false;
    }

    bool result =
        CryptGenRandom(
            hProv,
            32,
            challenge);

    CryptReleaseContext(
        hProv,
        0);

    return result;
}


// =========================================
// CREATE AUTHENTICATION HASH
// =========================================

bool createAuthenticationHash(
    const string& password,
    const BYTE challenge[32],
    string& result)
{
    string challengeData;

    for (int i = 0; i < 32; i++)
    {
        challengeData +=
            (char)challenge[i];
    }

    string authenticationData =
        password +
        challengeData;

    return calculateStringSHA256(
        authenticationData,
        result);
}


// =========================================
// CREATE AES-256 KEY
// =========================================

bool createAESKey(
    HCRYPTPROV hProv,
    HCRYPTKEY& hKey)
{
    BYTE keyData[32] =
    {
        0x10, 0x21, 0x32, 0x43,
        0x54, 0x65, 0x76, 0x87,
        0x98, 0xA9, 0xBA, 0xCB,
        0xDC, 0xED, 0xFE, 0x0F,

        0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC,
        0xDD, 0xEE, 0xFF, 0x00
    };

    BYTE keyBlob[
        sizeof(BLOBHEADER)
        + sizeof(DWORD)
        + 32
    ];

    BLOBHEADER* header =
        (BLOBHEADER*)keyBlob;

    header->bType =
        PLAINTEXTKEYBLOB;

    header->bVersion =
        CUR_BLOB_VERSION;

    header->reserved =
        0;

    header->aiKeyAlg =
        CALG_AES_256;

    DWORD* keyLength =
        (DWORD*)(
            keyBlob +
            sizeof(BLOBHEADER)
        );

    *keyLength = 32;

    BYTE* keyBytes =
        keyBlob +
        sizeof(BLOBHEADER)
        + sizeof(DWORD);

    memcpy(
        keyBytes,
        keyData,
        32
    );

    if (!CryptImportKey(
            hProv,
            keyBlob,
            sizeof(keyBlob),
            0,
            0,
            &hKey))
    {
        return false;
    }

    return true;
}


// =========================================
// SHA-256 FILE
// =========================================

bool calculateSHA256(
    const string& fileName,
    string& hashResult)
{
    ifstream file(
        fileName,
        ios::binary
    );

    if (!file)
    {
        return false;
    }

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(
            &hProv,
            NULL,
            NULL,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT))
    {
        return false;
    }

    if (!CryptCreateHash(
            hProv,
            CALG_SHA_256,
            0,
            0,
            &hHash))
    {
        CryptReleaseContext(
            hProv,
            0);

        return false;
    }

    char buffer[4096];

    while (
        file.read(
            buffer,
            sizeof(buffer))
        ||
        file.gcount() > 0)
    {
        DWORD bytesRead =
            (DWORD)file.gcount();

        if (!CryptHashData(
                hHash,
                (BYTE*)buffer,
                bytesRead,
                0))
        {
            CryptDestroyHash(hHash);

            CryptReleaseContext(
                hProv,
                0);

            file.close();

            return false;
        }
    }

    file.close();

    BYTE hash[32];

    DWORD hashSize =
        sizeof(hash);

    if (!CryptGetHashParam(
            hHash,
            HP_HASHVAL,
            hash,
            &hashSize,
            0))
    {
        CryptDestroyHash(hHash);

        CryptReleaseContext(
            hProv,
            0);

        return false;
    }

    stringstream ss;

    for (DWORD i = 0;
         i < hashSize;
         i++)
    {
        ss << hex
           << setw(2)
           << setfill('0')
           << (int)hash[i];
    }

    hashResult =
        ss.str();

    CryptDestroyHash(hHash);

    CryptReleaseContext(
        hProv,
        0);

    return true;
}


// =========================================
// DECRYPT FILE
// =========================================

bool decryptFile(
    const string& inputFileName,
    const string& outputFileName,
    HCRYPTKEY hKey)
{
    ifstream input(
        inputFileName,
        ios::binary
    );

    if (!input)
    {
        return false;
    }

    ofstream output(
        outputFileName,
        ios::binary
    );

    if (!output)
    {
        input.close();
        return false;
    }

    char buffer[4112];

    while (true)
    {
        input.read(
            buffer,
            4096
        );

        DWORD dataLength =
            (DWORD)input.gcount();

        if (dataLength == 0)
        {
            break;
        }

        bool isFinal = false;

        if (input.peek() == EOF)
        {
            isFinal = true;
        }

        if (!CryptDecrypt(
                hKey,
                0,
                isFinal,
                0,
                (BYTE*)buffer,
                &dataLength))
        {
            cout << "AES decryption failed!"
                 << endl;

            input.close();
            output.close();

            return false;
        }

        output.write(
            buffer,
            dataLength
        );

        if (isFinal)
        {
            break;
        }
    }

    input.close();
    output.close();

    return true;
}


// =========================================
// MAIN
// =========================================

int main()
{
    // =========================================
    // START WINSOCK
    // =========================================

    WSADATA wsa;

    if (WSAStartup(
            MAKEWORD(2, 2),
            &wsa) != 0)
    {
        cout << "Winsock startup failed!"
             << endl;

        return 1;
    }

    cout << "Winsock started successfully!"
         << endl;


    // =========================================
    // CREATE SERVER SOCKET
    // =========================================

    SOCKET serverSocket =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    if (serverSocket == INVALID_SOCKET)
    {
        cout << "Socket creation failed!"
             << endl;

        WSACleanup();

        return 1;
    }

    cout << "Server socket created successfully!"
         << endl;


    // =========================================
    // SERVER ADDRESS
    // =========================================

    sockaddr_in serverAddress;

    serverAddress.sin_family =
        AF_INET;

    serverAddress.sin_addr.s_addr =
        inet_addr("127.0.0.1");

    serverAddress.sin_port =
        htons(8080);


    // =========================================
    // BIND
    // =========================================

    if (bind(
            serverSocket,
            (sockaddr*)&serverAddress,
            sizeof(serverAddress)
        ) == SOCKET_ERROR)
    {
        cout << "Bind failed!"
             << endl;

        closesocket(serverSocket);

        WSACleanup();

        return 1;
    }

    cout << "Server bound to 127.0.0.1:8080"
         << endl;


    // =========================================
    // LISTEN
    // =========================================

    if (listen(
            serverSocket,
            5
        ) == SOCKET_ERROR)
    {
        cout << "Listen failed!"
             << endl;

        closesocket(serverSocket);

        WSACleanup();

        return 1;
    }

    cout << "Server is listening..."
         << endl;


    // =========================================
    // ACCEPT CLIENT
    // =========================================

    sockaddr_in clientAddress;

    int clientAddressSize =
        sizeof(clientAddress);

    SOCKET clientSocket =
        accept(
            serverSocket,
            (sockaddr*)&clientAddress,
            &clientAddressSize
        );

    if (clientSocket == INVALID_SOCKET)
    {
        cout << "Accept failed!"
             << endl;

        closesocket(serverSocket);

        WSACleanup();

        return 1;
    }

    cout << "Client connected!"
         << endl;


    // =========================================
    // AUTHENTICATION - RECEIVE USERNAME
    // =========================================

    string username;

    if (!receiveString(
            clientSocket,
            username))
    {
        cout << "Failed to receive username!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    cout << endl;

    cout << "Username received: "
         << username
         << endl;


    // =========================================
    // CHECK USERNAME
    // =========================================

    if (username != "admin")
    {
        cout << "Unknown username!"
             << endl;

        sendString(
            clientSocket,
            "AUTH_FAILED"
        );

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 0;
    }


    // =========================================
    // GENERATE RANDOM CHALLENGE
    // =========================================

    BYTE challenge[32];

    if (!generateChallenge(
            challenge))
    {
        cout << "Challenge generation failed!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    cout << "Random authentication challenge generated."
         << endl;


    // =========================================
    // SEND CHALLENGE
    // =========================================

    if (!sendAll(
            clientSocket,
            (char*)challenge,
            32))
    {
        cout << "Failed to send authentication challenge!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    cout << "Authentication challenge sent."
         << endl;


    // =========================================
    // RECEIVE AUTHENTICATION RESPONSE
    // =========================================

    string clientAuthHash;

    if (!receiveString(
            clientSocket,
            clientAuthHash))
    {
        cout << "Failed to receive authentication response!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    cout << "Authentication response received."
         << endl;


    // =========================================
    // CREATE EXPECTED AUTHENTICATION HASH
    // =========================================

    string expectedAuthHash;

    if (!createAuthenticationHash(
            "12345",
            challenge,
            expectedAuthHash))
    {
        cout << "Could not create authentication hash!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }


    // =========================================
    // CHECK AUTHENTICATION
    // =========================================

    if (clientAuthHash == expectedAuthHash)
    {
        cout << "Authentication successful!"
             << endl;

        if (!sendString(
                clientSocket,
                "AUTH_SUCCESS"))
        {
            closesocket(clientSocket);
            closesocket(serverSocket);
            WSACleanup();

            return 1;
        }
    }
    else
    {
        cout << "Authentication failed!"
             << endl;

        sendString(
            clientSocket,
            "AUTH_FAILED"
        );

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 0;
    }


    // =========================================
    // RECEIVE FILE NAME
    // =========================================

    string fileName;

    if (!receiveString(
            clientSocket,
            fileName))
    {
        cout << "Failed to receive file name!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    cout << endl;

    cout << "File name received: "
         << fileName
         << endl;


    // =========================================
    // RECEIVE AES IV
    // =========================================

    BYTE iv[16];

    if (!recvAll(
            clientSocket,
            (char*)iv,
            16))
    {
        cout << "Failed to receive AES IV!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    cout << "AES IV received successfully."
         << endl;


    // =========================================
    // RECEIVE ENCRYPTED FILE SIZE
    // =========================================

    uint64_t encryptedFileSize;

    if (!recvUint64(
            clientSocket,
            encryptedFileSize))
    {
        cout << "Failed to receive file size!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    cout << "Encrypted file size: "
         << encryptedFileSize
         << " bytes"
         << endl;


    // =========================================
    // RECEIVE ENCRYPTED FILE
    // =========================================

    string encryptedFile =
        "received_encrypted.bin";


    ofstream output(
        encryptedFile,
        ios::binary
    );

    if (!output)
    {
        cout << "Could not create encrypted file!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }


    char buffer[4096];

    uint64_t totalReceived = 0;


    while (
        totalReceived <
        encryptedFileSize)
    {
        uint64_t remaining =
            encryptedFileSize -
            totalReceived;

        int bytesToReceive =
            (remaining > 4096)
            ? 4096
            : (int)remaining;


        if (!recvAll(
                clientSocket,
                buffer,
                bytesToReceive))
        {
            cout << endl;

            cout << "Encrypted file transfer failed!"
                 << endl;

            output.close();

            closesocket(clientSocket);
            closesocket(serverSocket);
            WSACleanup();

            return 1;
        }


        output.write(
            buffer,
            bytesToReceive
        );


        totalReceived +=
            bytesToReceive;


        cout << "\rEncrypted data received: "
             << totalReceived
             << " / "
             << encryptedFileSize
             << " bytes"
             << flush;
    }


    output.close();


    cout << endl;

    cout << "Encrypted file received successfully!"
         << endl;


    // =========================================
    // START CRYPTOGRAPHIC PROVIDER
    // =========================================

    HCRYPTPROV hProv = 0;

    if (!CryptAcquireContext(
            &hProv,
            NULL,
            NULL,
            PROV_RSA_AES,
            CRYPT_VERIFYCONTEXT))
    {
        cout << "Cryptographic provider failed!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }


    // =========================================
    // CREATE AES KEY
    // =========================================

    HCRYPTKEY hKey = 0;

    if (!createAESKey(
            hProv,
            hKey))
    {
        cout << "AES key creation failed!"
             << endl;

        CryptReleaseContext(
            hProv,
            0);

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    cout << endl;

    cout << "AES-256 key created."
         << endl;


    // =========================================
    // SET AES IV
    // =========================================

    if (!CryptSetKeyParam(
            hKey,
            KP_IV,
            iv,
            0))
    {
        cout << "Failed to set AES IV!"
             << endl;

        CryptDestroyKey(hKey);

        CryptReleaseContext(
            hProv,
            0);

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }

    cout << "AES IV set successfully."
         << endl;


    // =========================================
    // DECRYPT FILE
    // =========================================

    string decryptedFile =
        "received_" + fileName;


    cout << "Decrypting file..."
         << endl;


    if (!decryptFile(
            encryptedFile,
            decryptedFile,
            hKey))
    {
        cout << "File decryption failed!"
             << endl;

        CryptDestroyKey(hKey);

        CryptReleaseContext(
            hProv,
            0);

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }


    cout << "File decrypted successfully!"
         << endl;


    // =========================================
    // CLEANUP AES
    // =========================================

    CryptDestroyKey(hKey);

    CryptReleaseContext(
        hProv,
        0);


    // =========================================
    // RECEIVE ORIGINAL SHA-256
    // =========================================

    string clientHash;

    if (!receiveString(
            clientSocket,
            clientHash))
    {
        cout << "Failed to receive SHA-256!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }


    cout << endl;

    cout << "SHA-256 received from client:"
         << endl;

    cout << clientHash
         << endl;


    // =========================================
    // CALCULATE SHA-256 OF DECRYPTED FILE
    // =========================================

    string serverHash;

    if (!calculateSHA256(
            decryptedFile,
            serverHash))
    {
        cout << "Could not calculate received file SHA-256!"
             << endl;

        closesocket(clientSocket);
        closesocket(serverSocket);
        WSACleanup();

        return 1;
    }


    cout << endl;

    cout << "SHA-256 of decrypted file:"
         << endl;

    cout << serverHash
         << endl;


    // =========================================
    // COMPARE HASHES
    // =========================================

    cout << endl;

    if (clientHash == serverHash)
    {
        cout << "===================================="
             << endl;

        cout << "INTEGRITY CHECK: PASSED"
             << endl;

        cout << "File is correct and unchanged."
             << endl;

        cout << "===================================="
             << endl;
    }
    else
    {
        cout << "===================================="
             << endl;

        cout << "INTEGRITY CHECK: FAILED"
             << endl;

        cout << "File hash does not match!"
             << endl;

        cout << "===================================="
             << endl;
    }


    // =========================================
    // CLOSE CONNECTION
    // =========================================

    closesocket(clientSocket);

    closesocket(serverSocket);

    WSACleanup();

    return 0;
}