#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <unordered_map>
#include <iostream>
#include <cstring>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define IN_OUT_LEN 1024
#define BUF_LEN 1024

#define REGISTER_STR "REGISTER"
#define LIST_STR "List"
#define SIGNOUT_STR "Exit"

// ============================== USER ==============================

struct User
{
    std::string name;
    std::string ip;
    int portNum_p2p;
    SSL *sd;
    int money;
    bool loggedIn;

    User(std::string);

    void Login(const std::string &, const std::string &, const int &, SSL *);
    void LogOut();
};

// ============================== GLOBAL VARIABLE ==============================

int sd_server;
RSA *privateKey = nullptr;
RSA *publicKey = nullptr;
X509 *cert = nullptr;
int loggedInUserCnt = 0;
std::unordered_map<std::string, User> usersList;

// ============================== FUNCTION DECLARATION ==============================

void *HandleRequest(void *);
int HandleString(const std::string &, const std::string &, SSL *, const int &);
void HandleRegister(const std::string &);
void HandleSignIn(const std::string &, const std::string &, const int &, SSL *);
void HandleList(const std::string &);
void HandleList(const std::string &, SSL *);
void HandleSignOut(const std::string &, SSL *);
void HandleTransaction(const std::string &, const std::string &, const int &);

// ============================== SSL FUCTION ==============================

RSA *generateRSAKey()
{
    RSA *rsa_key = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    if (RSA_generate_key_ex(rsa_key, 2048, e, NULL) != 1)
    {
        std::cerr << "Error generating RSA key pair.\n";
        RSA_free(rsa_key);
        BN_free(e);
        return nullptr;
    }

    BN_free(e);
    return rsa_key;
}

// Function to generate a self-signed X.509 certificate
X509 *generateSelfSignedCertificate(RSA *rsa_key)
{
    X509 *cert = X509_new();

    if (cert == nullptr)
    {
        std::cerr << "Error creating X.509 certificate.\n";
        return nullptr;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa_key);

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 31536000L); // 1 year validity
    X509_set_pubkey(cert, pkey);
    X509_sign(cert, pkey, EVP_sha256());

    EVP_PKEY_free(pkey);
    return cert;
}

SSL_CTX *createServerContext()
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        std::cerr << "Error creating SSL context.\n";
        return nullptr;
    }

    // Load the server certificate and private key
    if (SSL_CTX_use_RSAPrivateKey(ctx, privateKey) != 1)
    {
        std::cerr << "Error setting RSA private key.\n";
        RSA_free(privateKey);
        X509_free(cert);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Set the certificate
    if (SSL_CTX_use_certificate(ctx, cert) != 1)
    {
        std::cerr << "Error setting X.509 certificate.\n";
        RSA_free(privateKey);
        X509_free(cert);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    return ctx;
}

std::string getPublicKeyAsString(RSA *publicKey)
{
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, publicKey);

    char *ptr;
    size_t len = BIO_get_mem_data(bio, &ptr);
    std::string result(ptr, len);

    BIO_free(bio);
    return result;
}

std::string decryptRSA(const std::string &ciphertext, RSA *privateKey)
{
    int plaintext_len;
    unsigned char plaintext[RSA_size(privateKey)];

    plaintext_len = RSA_private_decrypt(ciphertext.length(), reinterpret_cast<const unsigned char *>(ciphertext.c_str()), plaintext, privateKey, RSA_PKCS1_PADDING);

    if (plaintext_len == -1)
    {
        // Decryption failed
        std::cerr << "RSA decryption failed.\n";
        ERR_print_errors_fp(stderr); // Print OpenSSL error stack
        return "";
    }

    return std::string(reinterpret_cast<char *>(plaintext), plaintext_len);
}

RSA *getPublicKeyFromString(const std::string &keyString)
{
    BIO *bio = BIO_new_mem_buf(keyString.c_str(), -1);
    RSA *publicKey = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);

    return publicKey;
}

std::string encryptRSA(const std::string &plaintext, RSA *publicKey)
{
    if (publicKey == nullptr)
    {
        std::cout << "publicKey is nullptr\n";
        return "bad";
    }
    int ciphertext_len;
    unsigned char ciphertext[RSA_size(publicKey)];

    ciphertext_len = RSA_public_encrypt(plaintext.length(), reinterpret_cast<const unsigned char *>(plaintext.c_str()), ciphertext, publicKey, RSA_PKCS1_PADDING);

    return std::string(reinterpret_cast<char *>(ciphertext), ciphertext_len);
}

// ------------------------------Main------------------------------

int main(int argc, char *argv[])
{
    privateKey = generateRSAKey();
    publicKey = RSAPublicKey_dup(privateKey);

    if (!privateKey)
    {
        std::cerr << "Error generating RSA key pair.\n";
        return 1;
    }

    // Generate self-signed X.509 certificate
    cert = generateSelfSignedCertificate(privateKey);
    if (!cert)
    {
        std::cerr << "Error generating X.509 certificate.\n";
        RSA_free(privateKey);
        return 1;
    }

    sd_server = socket(PF_INET, SOCK_STREAM, 0);
    if (sd_server < 0)
    {
        printf("Fail to create a client listening socket.\n");
        return 0;
    }

    int port = atoi(argv[1]);
    struct sockaddr_in selfAddr, otherAddr;
    selfAddr.sin_family = AF_INET;
    selfAddr.sin_addr.s_addr = INADDR_ANY;
    selfAddr.sin_port = htons(port);

    if (bind(sd_server, (const struct sockaddr *)&selfAddr, sizeof(selfAddr)) < 0)
    {
        perror("Bind socket failed!");
        close(sd_server);
        return 0;
    }

    if (listen(sd_server, 10) < 0)
    {
        perror("Listening error");
        return 0;
    }

    socklen_t len;
    len = sizeof(otherAddr);

    while (1)
    {
        int *sd_client = new int;
        *sd_client = accept(sd_server, (struct sockaddr *)&otherAddr, &len);
        // printf("connected by %s:%d\n", inet_ntoa(otherAddr.sin_addr),
        //        ntohs(otherAddr.sin_port));
        pthread_t pid;
        pthread_attr_t attr;

        pthread_attr_init(&attr);
        pthread_create(&pid, &attr, HandleRequest, (void *)sd_client);
        pthread_detach(pid);
    }

    close(sd_server);
}

// ------------------------------Thread------------------------------

void handleRequestSSL(SSL *ssl, std::string ipAddress, int port)
{
    const int BUFFER_SIZE = 1024;
    char *indata = new char[BUFFER_SIZE];
    // Receive data from the client
    while (1)
    {
        std::string req, res;
        int nbytes = SSL_read(ssl, indata, BUFFER_SIZE - 1);
        if (nbytes <= 0)
        {
            std::cerr << "Error receiving data from client.\n";
            break;
        }
        std::cout << "nbytes" << nbytes << "\n";
        req.append(indata, nbytes);
        HandleString(req, ipAddress, ssl, port);
    }

    // Send a response back to the client
    const char *response = "Hello from the server!";
    int bytesWritten = SSL_write(ssl, response, strlen(response));
    if (bytesWritten <= 0)
    {
        std::cerr << "Error sending response to client.\n";
        return;
    }

    std::cout << "Sent to client: " << response << std::endl;
}

void *HandleRequest(void *param)
{
    int sd_client = *(int *)param;
    char *indata = new char[IN_OUT_LEN];
    char *outdata = new char[IN_OUT_LEN];

    sockaddr_in peerAddr;
    socklen_t peerAddrLen = sizeof(peerAddr);

    char ipAddress[INET_ADDRSTRLEN];
    int port;

    if (getpeername(sd_client, (struct sockaddr *)&peerAddr, &peerAddrLen) == 0)
    {
        inet_ntop(AF_INET, &(peerAddr.sin_addr), ipAddress, INET_ADDRSTRLEN);
        port = ntohs(peerAddr.sin_port);
        std::cout << "Connected from: " << ipAddress << ":" << port << std::endl;
    }
    else
    {
        perror("getpeername failed");
    }

    SSL *ssl = SSL_new(createServerContext());
    if (!ssl)
    {
        std::cerr << "Error creating SSL object.\n";
        close(sd_client);
        return nullptr;
    }

    SSL_set_fd(ssl, sd_client);

    if (SSL_accept(ssl) <= 0)
    {
        std::cerr << "Error accepting SSL/TLS connection.\n";
        SSL_free(ssl);
        close(sd_client);
        return nullptr;
    }

    handleRequestSSL(ssl, ipAddress, port);

    close(sd_client);
    return 0;
}

// ------------------------------Struct functions------------------------------

User::User(std::string name)
{
    this->ip = "";
    this->portNum_p2p = -1;
    this->sd = nullptr;
    this->name = name;
    this->money = 10000;
    this->loggedIn = false;
}

void User::Login(const std::string &name, const std::string &ip, const int &portNum_p2p, SSL *sd)
{
    this->ip = ip;
    this->portNum_p2p = portNum_p2p;
    this->loggedIn = true;
    this->sd = sd;
}

void User::LogOut()
{
    this->ip = "";
    this->portNum_p2p = -1;
    this->loggedIn = false;
    this->sd = nullptr;
}

// ------------------------------Functions------------------------------

int HandleString(const std::string &req, const std::string &ip_client, SSL *sd_client, const int &port_server)
{
    size_t found = req.find('#');
    size_t foundSec = req.find_last_of('#');

    size_t foundEncrypted = req.find("Encrypted");

    if (foundEncrypted != std::string::npos)
    {
        std::string req_cypher = req.substr(9);
        std::string req_plain = decryptRSA(req_cypher, privateKey);
        std::cout << "\nPlaintext:\n"
                  << req_plain << " " << req_plain.size() << "\n";
        HandleString(req_plain, ip_client, sd_client, port_server);
        return 0;
    }

    if (found == foundSec)
    {
        // 有一個 '#'
        if (found != std::string::npos)
        {
            std::string first = req.substr(0, found);
            std::string second = req.substr(found + 1, req.size() - found - 1);

            // 註冊;
            if (first.compare(REGISTER_STR) == 0)
            {
                if (usersList.find(second) == usersList.end())
                {
                    HandleRegister(second);
                    const char *res = "100 OK\n";
                    SSL_write(sd_client, res, strlen(res));
                }
                else
                {
                    std::cout << "已經註冊過了\n";
                    const char *res = "210 FAIL: 已經註冊過了\n";
                    SSL_write(sd_client, res, strlen(res));
                }
            }
            // 登入
            else
            {
                if (usersList.find(first) != usersList.end())
                {
                    if (usersList.at(first).loggedIn == true)
                    {
                        std::cout << "已從其他裝置註冊\n";
                        const char *res = "210 logged in fail: 已從其他裝置註冊\n";
                        SSL_write(sd_client, res, strlen(res));
                    }
                    else
                        HandleSignIn(first, ip_client, stoi(second), sd_client);
                }
                else
                {
                    std::cout << "尚未註冊\n";
                    const char *res = "210 logged in fail: 尚未註冊\n";
                    SSL_write(sd_client, res, strlen(res));
                }
            }
        }
        // 沒有 '#'
        else
        {
            if (req.compare(LIST_STR) == 0)
            {
                HandleList(ip_client, sd_client);
            }
            else if (req.compare(SIGNOUT_STR) == 0)
            {
                HandleSignOut(ip_client, sd_client);
                const char *res = "Bye";
                SSL_write(sd_client, res, strlen(res));
            }
        }
    }
    // 有兩個 '#'
    else if (found != std::string::npos)
    {
        std::string sender = req.substr(0, found);
        std::string money_str = req.substr(found + 1, foundSec - found - 1);
        int money = std::stoi(money_str);
        std::string receiver = req.substr(foundSec + 1, req.size() - foundSec - 1);
        std::cout << sender << " " << money_str << " " << receiver << "\n";
        HandleTransaction(sender, receiver, money);
    }

    return 0;
}

void HandleRegister(const std::string &name)
{
    std::cout << "HandleRegister " << name << "\n";
    User newUser(name);
    usersList.insert({name, newUser});
    return;
}

void HandleSignIn(const std::string &name, const std::string &ip, const int &portNum_p2p, SSL *sd)
{
    std::cout << "HandleSignIn " << ip << " " << portNum_p2p << "\n";
    User &targetUsr = usersList.at(name);
    targetUsr.Login(name, ip, portNum_p2p, sd);
    loggedInUserCnt++;
    HandleList(name);
}

void HandleList(const std::string &name)
{
    User &targetUsr = usersList.at(name);
    std::string str;
    std::string publicKeyStr = getPublicKeyAsString(publicKey);
    str += (std::to_string(targetUsr.money) + '\n' + publicKeyStr + '\n' + std::to_string(loggedInUserCnt) + '\n');
    for (auto &x : usersList)
    {
        if (x.second.loggedIn == false)
            continue;
        str += (x.second.name + '#' + x.second.ip + '#' + std::to_string(x.second.portNum_p2p) + '\n');
    }
    std::cout << str;
    const char *res = str.c_str();
    SSL_write(targetUsr.sd, res, strlen(res));
    // return str;
}

void HandleList(const std::string &ip, SSL *sd)
{
    std::string str_list;
    std::string str_info;

    for (auto &x : usersList)
    {
        if (x.second.loggedIn == false)
            continue;
        str_list += (x.second.name + '#' + x.second.ip + '#' + std::to_string(x.second.portNum_p2p) + '\n');
        if (x.second.ip == ip && x.second.sd == sd)
        {
            str_info += (std::to_string(x.second.money) + '\n' + "public key" + '\n' + std::to_string(loggedInUserCnt) + '\n');
        }
    }
    std::string str = str_info + str_list;
    std::cout << str;
    const char *res = str.c_str();
    SSL_write(sd, res, strlen(res));
}

void HandleSignOut(const std::string &ip, SSL *sd)
{
    for (auto &x : usersList)
    {
        if (x.second.ip == ip && x.second.sd == sd)
        {
            x.second.LogOut();
            loggedInUserCnt--;
        }
    }
}

void HandleTransaction(const std::string &sender, const std::string &receiver, const int &money)
{
    if (usersList.find(sender) != usersList.end() && usersList.find(receiver) != usersList.end())
    {
        if (usersList.at(sender).money < money)
        {
            const char *res = "你沒那麼多錢 ：（\n";
            SSL_write(usersList.at(sender).sd, res, strlen(res));
            return;
        }
        usersList.at(sender).money -= money;
        usersList.at(receiver).money += money;
        const char *res = "succeeded\n";
        SSL_write(usersList.at(sender).sd, res, strlen(res));
    }
    else
    {
        const char *res = "查無此用戶\n";
        SSL_write(usersList.at(sender).sd, res, strlen(res));
    }
}