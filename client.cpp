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
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/err.h>

// #define SERVER_IP "127.0.0.1"
// #define SERVER_PORT 8888
#define BLEN 1024
#define MAX_CHAR_LENGTH 20

#define DOING_NOTHING -1
#define REGISTERING 0
#define SIGNING_IN 1
#define ASK_FOR_LIST 2
#define SIGNING_OUT 3
#define TRANSACTION 4

struct Addr
{
    char *ip;
    int port;
};

int HandleSelect();
void HandleRegister();
void HandleSignIn();
void HandleList();
void HandleSignOut();
void HandleTransaction();
int Recieve();
void Recieve_List(std::string, std::string);
void *ListenTransaction(void *param);

int n, buf_len = BLEN;
char buf[BLEN];

int state = DOING_NOTHING;
int sd;
SSL *ssl = nullptr;
RSA *rsaServer = nullptr;

bool isLoggedIn = false;
std::string loggedInUser;

int sd_listen, sd_other, sd_send;
int n_listen, buf_len_listen = BLEN;
char buf_listen[BLEN];
RSA *myPrivateKey = nullptr;
RSA *myPublicKey = nullptr;
RSA *peerPublicKey = nullptr;
X509 *myCert = nullptr;

std::unordered_map<std::string, Addr> userList;

// ============================== SSL Function ==============================

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
    if (SSL_CTX_use_RSAPrivateKey(ctx, myPrivateKey) != 1)
    {
        std::cerr << "Error setting RSA private key.\n";
        RSA_free(myPrivateKey);
        X509_free(myCert);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Set the certificate
    if (SSL_CTX_use_certificate(ctx, myCert) != 1)
    {
        std::cerr << "Error setting X.509 certificate.\n";
        RSA_free(myPrivateKey);
        X509_free(myCert);
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

    // std::cout << "Result\n"<< result << "\nResult";
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

// ============================== Main ==============================

int main(int argc, char *argv[])
{
    myPrivateKey = generateRSAKey();
    myPublicKey = RSAPublicKey_dup(myPrivateKey);

    const char *SERVER_IP = argv[1];
    const int SERVER_PORT = stoi(static_cast<std::string>(argv[2]));

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    if (!myPrivateKey)
    {
        std::cerr << "Error generating RSA key pair.\n";
        return 1;
    }

    // Generate self-signed X.509 certificate
    myCert = generateSelfSignedCertificate(myPrivateKey);
    if (!myCert)
    {
        std::cerr << "Error generating X.509 certificate.\n";
        RSA_free(myPrivateKey);
        return 1;
    }

    SSL_CTX *sslContext = SSL_CTX_new(TLS_client_method());
    if (!sslContext)
    {
        std::cerr << "Error creating SSL context.\n";
        return 1;
    }

    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0)
    {
        std::cout << "Create Socket Failed !!!\n";
        SSL_CTX_free(sslContext);
        return 0;
    }
    std::cout << "Created Socket !!!\n";

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    inet_aton(SERVER_IP, &serverAddr.sin_addr);
    serverAddr.sin_port = htons(SERVER_PORT);

    int returnCode = connect(sd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    std::cout << "return code is: " << returnCode << "\n";
    if (returnCode < 0)
    {
        std::cout << "Failed !\n";
        close(sd);
        SSL_CTX_free(sslContext);
        return 0;
    }
    else
        std::cout << "Success !\n";

    ssl = SSL_new(sslContext);
    SSL_set_fd(ssl, sd);

    if (SSL_connect(ssl) != 1)
    {
        std::cerr << "Error performing SSL/TLS handshake.\n";
        SSL_free(ssl);
        close(sd);
        SSL_CTX_free(sslContext);
        return 1;
    }

    while (true)
    {
        state = HandleSelect();

        switch (state)
        {
        case REGISTERING:
            HandleRegister();
            break;
        case SIGNING_IN:
            HandleSignIn();
            break;
        case ASK_FOR_LIST:
            HandleList();
            break;
        case SIGNING_OUT:
            HandleSignOut();
            close(sd_listen);
            break;
        case TRANSACTION:
            HandleTransaction();
            break;
        default:
            state = DOING_NOTHING;
            break;
        }

        if (state == SIGNING_OUT)
            break;
    }

    sleep(1);
    // Close the SSL connection
    SSL_shutdown(ssl);
    SSL_free(ssl);

    // Close the socket
    close(sd);

    // Clean up SSL context
    SSL_CTX_free(sslContext);

    ERR_free_strings();
    EVP_cleanup();
}

// ============================== Functions ==============================

int HandleSelect()
{
    std::cout << "[選單]\n註冊請按 0\n登入請按 1\n最新的帳戶餘額與上線清單請按 2\n登出請按 3\n轉帳請按 4\n";
    std::string input;
    std::cin >> input;
    try
    {
        int input_i = stoi(input);
        if (input_i >= 0 && input_i <= 4)
        {
            return input_i;
        }
    }
    catch (std::exception &e)
    {
        std::cout << "\n輸入格式不符！\n";
    }
    return -1;
}

int Recieve()
{
    // char* buf_ptr = buf;
    if ((n = SSL_read(ssl, buf, buf_len)) < 0)
    {
        std::cout << "\nError when recieving\n";
        return -1;
    }

    std::cout << "\n";
    std::string res;
    for (int i = 0; i < n; i++)
    {
        res += buf[i];
    }
    std::cout << res;
    std::cout << "\n";

    int pkStartIdx = res.find_first_of('-');
    int pkEndIdx = res.find_last_of('-');
    if (pkStartIdx != std::string::npos && pkEndIdx != std::string::npos)
    {
        std::string pk = res.substr(pkStartIdx, pkEndIdx - pkStartIdx + 2);
        rsaServer = getPublicKeyFromString(pk);
    }

    if (n >= 4 && buf[0] == '2' && buf[3] == ' ')
        return -1;
    return n;
}

void Recieve_List(std::string giver, std::string receiver)
{
    if ((n = SSL_read(ssl, buf, buf_len)) < 0)
    {
        std::cout << "\nError when recieving\n";
        return;
    }

    if (n >= 4 && buf[0] == '2' && buf[3] == ' ')
        return;

    std::string resStr(buf);
    std::cout << resStr << "\n";
    int sliceIdx[4] = {-1};
    int j = 0;
    for (int i = 0; i < n; i++)
    {
        if (buf[i] == '\n')
        {
            if (j == 0)
            {
                sliceIdx[j] = i + 1;
                j++;
            }
            else if (j == 3)
            {
                sliceIdx[j] = i + 1;
                char *userName = new char[sliceIdx[1] - sliceIdx[0]];
                strncpy(userName, buf + sliceIdx[0], sliceIdx[1] - sliceIdx[0] - 1);
                userName[sliceIdx[1] - sliceIdx[0] - 1] = '\0';
                if (strcmp(userName, giver.c_str()) != 0 || strcmp(userName, receiver.c_str()) != 0)
                {
                    char *userIP = new char[sliceIdx[2] - sliceIdx[1]];
                    strncpy(userIP, buf + sliceIdx[1], sliceIdx[2] - sliceIdx[1] - 1);

                    char *userPortStr = new char[sliceIdx[3] - sliceIdx[2]];
                    strncpy(userPortStr, buf + sliceIdx[2], sliceIdx[3] - sliceIdx[2] - 1);

                    int userPort;
                    userPort = atoi(userPortStr);
                    userList[userName] = {userIP, userPort};
                }
                sliceIdx[0] = i + 1;
                j = 1;
                delete[] userName;
            }
            else
            {
                j = 0;
            }
        }
        else if (buf[i] == '#')
        {
            if (j == 1 || j == 2)
            {
                sliceIdx[j] = i + 1;
                j++;
            }
            else
            {
                j = 0;
            }
        }
    }
    return;
}

void Recieve_peer(int sd_p2p)
{
    // char* buf_ptr = buf;
    char buf[BLEN];
    if ((n = read(sd_p2p, buf, BLEN - 1)) < 0)
    {
        std::cout << "\nError when recieving\n";
        return;
    }

    std::cout << "\n";
    std::string res;
    for (int i = 0; i < n; i++)
    {
        res += buf[i];
    }
    
    peerPublicKey = getPublicKeyFromString(res);

    return;
}

void HandleRegister()
{
    if (isLoggedIn)
    {
        std::cout << "請先登出\n";
        return;
    }
    std::string registerName;
    std::cout << "[註冊]請輸入使用者名稱\n";
    std::cin >> registerName;
    std::string req_str = "REGISTER#" + registerName;
    const char *req = req_str.c_str();
    SSL_write(ssl, req, strlen(req));

    Recieve();
}

void HandleSignIn()
{
    if (isLoggedIn)
    {
        std::cout << "請先登出\n";
        return;
    }
    std::string signinName;
    std::cout << "[登入]請輸入<使用者名稱>#<PortNum>\n";
    std::cin >> signinName;
    const char *req = signinName.c_str();

    for (int i = 0; i < signinName.size(); i++)
    {
        if (signinName[i] == '#')
        {
            loggedInUser = signinName.substr(0, i);
            break;
        }
    }
    int sliceIdx = -1;
    for (int i = 0; i < signinName.size(); i++)
    {
        if (signinName[i] == '#')
        {
            sliceIdx = i + 1;
        }
    }
    std::string port = signinName.substr(sliceIdx, signinName.size() - sliceIdx);
    int *portNum = new int;
    *portNum = stoi(port);
    if (*portNum < 1024 || *portNum > 65535)
    {
        std::cout << "Port Number必須介於1024到65535\n";
        return;
    }

    SSL_write(ssl, req, strlen(req));
    int ok = Recieve();
    if (ok != -1)
    {
        isLoggedIn = true;

        pthread_t pid;
        pthread_attr_t attr;

        pthread_attr_init(&attr);
        pthread_create(&pid, &attr, ListenTransaction, portNum);
        pthread_detach(pid);
    }
}

void HandleList()
{
    if (!isLoggedIn)
    {
        std::cout << "請先登入\n";
        return;
    }
    std::string reqStr_plain = "List";
    std::string reqStr = "Encrypted" + encryptRSA(reqStr_plain, rsaServer);
    SSL_write(ssl, reqStr.c_str(), reqStr.length());

    Recieve();
}

void HandleSignOut()
{
    std::string reqStr_plain = "Exit";
    std::string reqStr = "Encrypted" + encryptRSA(reqStr_plain, rsaServer);
    SSL_write(ssl, reqStr.c_str(), reqStr.length());

    Recieve();
    isLoggedIn = false;
}

void HandleTransaction()
{
    if (!isLoggedIn)
    {
        std::cout << "請先登入\n";
        return;
    }
    std::cout << "[轉帳]請輸入<轉出者名稱>#<轉出金額>#<轉入者名稱>\n";
    std::string input;
    std::cin >> input;
    std::string inputArr[3];
    int j = 0, begin = 0;

    for (int i = 0; i < input.size(); i++)
    {
        if (input[i] == '#')
        {
            inputArr[j] = input.substr(begin, i - begin);
            begin = i + 1;
            j++;
            if (j > 2)
                break;
        }
        else if (i == input.size() - 1)
        {
            inputArr[j] = input.substr(begin, i - begin + 1);
        }
    }
    if (j != 2)
    {
        std::cout << "輸入格式錯誤\n";
        return;
    }

    if (inputArr[0].compare(loggedInUser) != 0)
    {
        std::cout << "不可由他人帳號轉出\n";
        return;
    }

    if (inputArr[2].compare(loggedInUser) == 0)
    {
        std::cout << "不可轉給自己\n";
        return;
    }

    const char *req = "List";
    SSL_write(ssl, req, strlen(req));

    Recieve_List(inputArr[0], inputArr[2]);
    
    if (userList.find(inputArr[2]) == userList.end())
    {
        std::cout << "查無此用戶或此用戶不在線上\n";
        return;
    }
    const char *p2p_IP = userList[inputArr[2]].ip;
    const int p2p_PORT = userList[inputArr[2]].port;

    sd_send = socket(AF_INET, SOCK_STREAM, 0);
    if (sd_send < 0)
    {
        std::cout << "Create Socket Failed !!!\n";
        return;
    }

    struct sockaddr_in p2pAddr;
    p2pAddr.sin_family = AF_INET;
    inet_aton(p2p_IP, &p2pAddr.sin_addr);
    p2pAddr.sin_port = htons(p2p_PORT);

    int returnCode = connect(sd_send, (struct sockaddr *)&p2pAddr, sizeof(p2pAddr));
    if (returnCode < 0)
    {
        std::cout << "Failed !\n";
        return;
    }

    std::string askKey = "Key";

    send(sd_send, askKey.c_str(), askKey.length(), 0);

    Recieve_peer(sd_send);

    std::string cipherTxt = encryptRSA(input, peerPublicKey);

    send(sd_send, cipherTxt.c_str(), cipherTxt.length(), 0);

    close(sd_send);

    Recieve();
}

void *ListenTransaction(void *param)
{
    sd_listen = socket(PF_INET, SOCK_STREAM, 0);
    if (sd_listen < 0)
    {
        printf("Fail to create a client listening socket.\n");
        return (int *)-1;
    }

    struct sockaddr_in selfAddr, otherAddr;
    selfAddr.sin_family = AF_INET;
    selfAddr.sin_addr.s_addr = INADDR_ANY;
    selfAddr.sin_port = htons(*((int *)param));

    if (bind(sd_listen, (const struct sockaddr *)&selfAddr, sizeof(selfAddr)) < 0)
    {
        perror("Bind socket failed!");
        close(sd_listen);
        return (int *)-1;
    }
    if (listen(sd_listen, 5) < 0)
    {
        perror("Listening error");
        return (int *)-1;
    }

    socklen_t len;
    len = sizeof(otherAddr);
    char *indata = new char[BLEN];
    char *outdata = new char[BLEN];
    while (1)
    {
        sd_other = accept(sd_listen, (struct sockaddr *)&otherAddr, &len);
        printf("connected by %s:%d\n", inet_ntoa(otherAddr.sin_addr),
               ntohs(otherAddr.sin_port));

        std::cout << "accepted !!!"
                  << "\n";

        std::string req;
        while (true)
        {
            std::cout << "有進來\n";
            int nbytes = read(sd_other, indata, BLEN - 1);
            if (nbytes <= 0)
            {
                close(sd_other);
                printf("client closed connection.\n");
                break;
            }
            req = "";
            req.append(indata, nbytes);
            std::cout << "received: " << req;
            if (req.compare("Key") == 0)
            {
                std::string myPkStr = getPublicKeyAsString(myPublicKey);
                send(sd_other, myPkStr.c_str(), myPkStr.length(), 0);
            }
        }
        std::string plain = decryptRSA(req, myPrivateKey);
        std::cout << "有交易 : " << plain << '\n';
        SSL_write(ssl, plain.c_str(), strlen(plain.c_str()));
    }
}