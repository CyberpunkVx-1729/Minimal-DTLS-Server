#include "DTLS_server.h"

DTLS_SERVER::DTLS_SERVER()
{
#ifdef WIN32
	int err = WSAStartup(this->wVersionRequested, &this->wsaData);
	if (err != 0)
	{
		if (this->verbose)
			printf("WSAStartup failed with error: %d, WSAE#%d\n", err, WSAGetLastError());

		perror("WSAStartup()");
		exit(EXIT_FAILURE);
	}
#endif

	memset(&server_addr, 0, sizeof(struct sockaddr_in));


}

DTLS_SERVER::~DTLS_SERVER()
{
}


void DTLS_SERVER::setup_server(const char* server_ip_address, unsigned short server_port, bool verbosity)
{
	//Setup Server Address & port
	memset((char*)this->server_ip_addr, 0, sizeof(char));
	strcpy(this->server_ip_addr, server_ip_address);
	this->server_port = server_port;

	//Verbosity
	this->verbose = verbosity;

	//Setup (SERVER) local address
	this->server_addr.sin_family = AF_INET;
	this->server_addr.sin_port = htons(this->server_port);
	this->server_addr.sin_addr.s_addr = inet_addr(this->server_ip_addr);

	//Setup OpenSSL for multi threading
	this->__thread_prepare();

	//Init OpenSSL
	OpenSSL_add_ssl_algorithms();
	SSL_load_error_strings();

	//Create new Context
	this->ctx = SSL_CTX_new(DTLSv1_server_method());
	if (this->ctx == nullptr)
	{
		if (this->verbose)
		{
			printf("SSL: Unable to create Context\n");
		}
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE + 1);
	}

	//Load certificate File
	if (!SSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM))
	{
		printf("SSL: No Certificate found!\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE + 2);
	}

	//Load private Key File
	if (!SSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM))
	{
		printf("SSL: No Private Key found!\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE + 3);
	}

	//Check Private Key
	if (!SSL_CTX_check_private_key(ctx))
	{
		printf("SSL: Invalid Private Key found!\n");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE + 4);
	}

	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, __OPENSSL_dtls_verify_callback);
	SSL_CTX_set_read_ahead(ctx, 1);
	SSL_CTX_set_cookie_generate_cb(ctx, __OPENSSL_generate_cookie);
	SSL_CTX_set_cookie_verify_cb(ctx, &__OPENSSL_verify_cookie);

	//Setup Server
	this->__setup_socket();

}

void DTLS_SERVER::start_server()
{
	//Start communication loop
	this->__start_listening();
}

void DTLS_SERVER::__CRYPTO_locking_function(int mode, int n, const char* file, int line)
{
	if (mode & CRYPTO_LOCK)
	#ifdef WIN32
			WaitForSingleObject(mutex_buf[n], INFINITE);
		else
			ReleaseMutex(mutex_buf[n]);
	#else
			pthread_mutex_lock(&__mutex_buf[n]);
		else
			pthread_mutex_unlock(&__mutex_buf[n]);
	#endif
}

unsigned long DTLS_SERVER::__CRYPTO_id_function(void)
{
	#ifdef WIN32
		return (unsigned long)GetCurrentThreadId();
	#else
		return (unsigned long)pthread_self();
	#endif
}

int DTLS_SERVER::__thread_prepare()
{
	//Allocate Memory for Mutexes
	#ifdef WIN32
		mutex_buf = (HANDLE*)malloc(CRYPTO_num_locks() * sizeof(HANDLE));
	#else
		__mutex_buf = (pthread_mutex_t*)malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
	#endif

	//Init each mutex
	for (int i = 0; i < CRYPTO_num_locks(); i++)
	{
		#ifdef WIN32
			this->mutex_buf[i] = CreateMutex(NULL, FALSE, NULL);
		#else
			pthread_mutex_init(&__mutex_buf[i], NULL);
		#endif
	}

	//Setup OpenSSL CRYPTO Callbacks
	CRYPTO_set_id_callback(__CRYPTO_id_function);
	CRYPTO_set_locking_callback(__CRYPTO_locking_function);
	return 1;
}

int DTLS_SERVER::__thread_cleanup()
{
	int i;

	if (!__mutex_buf)
		return 0;

	CRYPTO_set_id_callback(NULL);
	CRYPTO_set_locking_callback(NULL);

	for (i = 0; i < CRYPTO_num_locks(); i++)
	{
	#ifdef WIN32
			CloseHandle(mutex_buf[i]);
	#else
			pthread_mutex_destroy(&__mutex_buf[i]);
	#endif
	}

	//Cleanup
	free(__mutex_buf);
	__mutex_buf = NULL;
	return 1;
}

void DTLS_SERVER::__setup_socket()
{
	//Create Socket
	this->sock = socket(this->server_addr.sin_family, SOCK_DGRAM, IPPROTO_UDP);
	if (this->sock < 0)
	{
		if (this->verbose)
		{
			#ifdef WIN32
					printf("NET: Unable to create socket,  WSAE#%d\n", WSAGetLastError());
			#else
					printf("NET: Unable to create socket...\n");
					perror("socket");
			#endif
		}

		perror("socket()");
		exit(EXIT_FAILURE + 5);
	}

	//Set Socket Options
	const int on = 1;
	#ifdef WIN32
		setsockopt(this->sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, (socklen_t)sizeof(on));
	#else
		setsockopt(this->sock, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, (socklen_t)sizeof(on));
		#if defined(SO_REUSEPORT) && !defined(__linux__)
			setsockopt(this->sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&on, (socklen_t)sizeof(on));
		#endif
	#endif

	//Bind Socket to local address
	if (bind(this->sock, (const struct sockaddr*)&this->server_addr, sizeof(struct sockaddr_in)))
	{
		if (this->verbose)
		{
			#ifdef WIN32
					printf("NET: Unable to bind socket,  WSAE#%d\n", WSAGetLastError());
			#else
					printf("NET: Unable to bind socket...\n");
					perror("bind");
			#endif
		}

		perror("bind()");
		exit(EXIT_FAILURE + 6);
	}


}

void DTLS_SERVER::__start_listening()
{
	//Start receiving incoming Connections from clients
	while (this->stop_reception == false)
	{
		memset(&client_addr, 0, sizeof(struct sockaddr_in));

		/* Create BIO */
		bio = BIO_new_dgram(this->sock, BIO_NOCLOSE);
		if (bio == nullptr)
		{
			printf("SSL:Unable to create a BIO Object!\n");
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE + 7);
		}

		/* Set and activate timeouts */
		timeout.tv_sec = 3;
		timeout.tv_usec = 0;
		BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

		//Create an SSL Object
		ssl = SSL_new(ctx);
		if (ssl == nullptr)
		{
			printf("SSL:Unable to create an SSL Object!\n");
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE + 7);
		}

		//Set SSL Options
		SSL_set_bio(ssl, bio, bio);
		SSL_set_options(ssl, SSL_OP_COOKIE_EXCHANGE);


		//Start Listening for incoming connections
		int ret = 0;
		while (((ret = DTLSv1_listen(ssl, (void*)&client_addr)) <= 0) && this->stop_reception == false)
		{
			fprintf(stderr, "ret %d : %s\n", ret, strerror(errno));
			ERR_print_errors_fp(stderr);
		}

		//When a new CLIENT connect
		THREAD_ARG new_thread_arg;
		memcpy(&new_thread_arg.server_addr, &server_addr, sizeof(struct sockaddr_in));
		memcpy(&new_thread_arg.client_addr, &client_addr, sizeof(struct sockaddr_in));
		new_thread_arg.ssl = ssl;
		thread_args.push_back(new_thread_arg);

#ifdef WIN32
		if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)__handle_client, info, 0, &tid) == NULL) {
			exit(-1);
		}
#else

		int current_arg = thread_args.size();
		if (pthread_create(&new_thread_arg.tid, NULL, __handle_client, &new_thread_arg) != 0) {
			perror("pthread_create");
			exit(-1);
		}
#endif

	}

	this->__thread_cleanup();
}

void* DTLS_SERVER::__handle_client(void* thread_arg)
{
	ssize_t len;
	char addrbuf[INET_ADDRSTRLEN];
	THREAD_ARG* pThread_args = (THREAD_ARG*)thread_arg;
	SSL* ssl = pThread_args->ssl;
	int sock, reading = 0, ret = 0;
	const int on = 1, off = 0;
	struct timeval timeout;
	int num_timeouts = 0, max_timeouts = 5;
	char error_buf[1000] = {0};

#ifndef WIN32
	pthread_detach(pthread_self());
#endif

	//Some assertions
	//OPENSSL_assert(pThread_args->client_addr.sin_family == pThread_args->server_addr.sin_family);

	//Create a socket
	sock = socket(pThread_args->client_addr.sin_family, SOCK_DGRAM, 0);
	if (sock < 0) 
	{
		printf("SSL:Unable to create a SOCKET!\n");
		perror("socket");
		goto __GOTO_CLEANUP;
	}

	//Set Socket options
	#ifdef WIN32
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, (socklen_t)sizeof(on));
	#else
		setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const void*)&on, (socklen_t)sizeof(on));
	#if defined(SO_REUSEPORT) && !defined(__linux__)
		setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const void*)&on, (socklen_t)sizeof(on));
	#endif
	#endif

	//Bind Socket
	switch (pThread_args->client_addr.sin_family) 
	{
	case AF_INET:
		if (bind(sock, (const struct sockaddr*)&pThread_args->server_addr, sizeof(struct sockaddr_in))) 
		{
			printf("NET: Unable to bind socket !\n");
			perror("bind");
			goto __GOTO_CLEANUP;
		}
		if (connect(sock, (struct sockaddr*)&pThread_args->client_addr, sizeof(struct sockaddr_in))) 
		{
			printf("NET: Unable to connect socket !\n");
			perror("connect");
			goto __GOTO_CLEANUP;
		}
		break;
	default:
		OPENSSL_assert(0);
		break;
	}

	// Set new socket and set BIO to connected
	BIO_set_fd(SSL_get_rbio(ssl), sock, BIO_NOCLOSE);
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &pThread_args->client_addr);

	// Finish handshake
	do { ret = SSL_accept(ssl); } while (ret == 0);
	if (ret < 0) 
	{
		perror("SSL_accept");
		printf("%s\n", ERR_error_string(ERR_get_error(), error_buf));
		goto __GOTO_CLEANUP;
	}

	/* Set and activate timeouts */
	timeout.tv_sec = 5;
	timeout.tv_usec = 0;
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout);

	printf("\nThread %lx: accepted connection from %s:%d\n", __CRYPTO_id_function(),
		inet_ntop(AF_INET, &pThread_args->client_addr.sin_addr, addrbuf, INET_ADDRSTRLEN),
		ntohs(pThread_args->client_addr.sin_port));

	if (SSL_get_peer_certificate(ssl)) 
	{
		printf("------------------------------------------------------------\n");
		X509_NAME_print_ex_fp(stdout, X509_get_subject_name(SSL_get_peer_certificate(ssl)),
			1, XN_FLAG_MULTILINE);
		printf("\n\n Cipher: %s", SSL_CIPHER_get_name(SSL_get_current_cipher(ssl)));
		printf("\n------------------------------------------------------------\n\n");
	}


	//-------------------------------------------
	//COMMUNICATION GOES HERE :
	//-------------------------------------------

	//Recv message
	len = SSL_read(ssl, error_buf, sizeof(error_buf));
	printf("read %d bytes [%s]\n", (int)len, error_buf);

	//Send
	len = SSL_write(ssl, "Hello from Server", sizeof("Hello from Server"));

	//-------------------------------------------
	//-------------------------------------------
	//-------------------------------------------



__GOTO_CLEANUP:
#ifdef WIN32
	closesocket(fd);
#else
	close(sock);
#endif
	//free(thread_arg);
	SSL_free(ssl);
	if (sock)
		printf("Thread %lx: done, connection closed.\n", __CRYPTO_id_function());
#if WIN32
	ExitThread(0);
#else
	pthread_exit((void*)NULL);
#endif

}

int DTLS_SERVER::__OPENSSL_dtls_verify_callback(int ok, X509_STORE_CTX* ctx)
{
	/*TODO: Here we check if we trust the certificate ! */
	return 1;
}

int DTLS_SERVER::__OPENSSL_generate_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len)
{
	unsigned char* buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength = 0;
	struct sockaddr_in peer;

	/* Initialize a random secret */
	if (!cookie_initialized)
	{
		if (!RAND_bytes(cookie_secret, COOKIE_SECRET_LENGTH))
		{
			printf("SSL_GC: error setting random cookie secret\n");
			return 0;
		}
		cookie_initialized = 1;
	}

	/* Read peer information */
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.sin_family) 
	{
	case AF_INET:
		length += sizeof(struct in_addr);
		break;
	default:
		OPENSSL_assert(0);
		break;
	}

	length += sizeof(unsigned short);
	buffer = (unsigned char*)OPENSSL_malloc(length);

	if (buffer == NULL)
	{
		printf("SSL_GC: out of memory\n");
		return 0;
	}

	switch (peer.sin_family) 
	{
	case AF_INET:
		memcpy(buffer, &peer.sin_port, sizeof(unsigned short));
		memcpy(buffer + sizeof(peer.sin_port),&peer.sin_addr, sizeof(struct in_addr));
		break;
	default:
		OPENSSL_assert(0);
		break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH,
		(const unsigned char*)buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	memcpy(cookie, result, resultlength);
	*cookie_len = resultlength;

	return 1;
}

int DTLS_SERVER::__OPENSSL_verify_cookie(SSL* ssl, unsigned char* cookie, unsigned int cookie_len)
{
	unsigned char* buffer, result[EVP_MAX_MD_SIZE];
	unsigned int length = 0, resultlength = 0;
	struct sockaddr_in peer;

	/* Initialize a random secret */
	if (!cookie_initialized)
	{
		printf("SSL_GC: cookie not initialised ...\n");
		return 0;
	}

	/* Read peer information */
	(void)BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

	/* Create buffer with peer's address and port */
	length = 0;
	switch (peer.sin_family) 
	{
		case AF_INET:
			length += sizeof(struct in_addr);
			break;
		default:
			OPENSSL_assert(0);
			break;
	}
	length += sizeof(unsigned short);
	buffer = (unsigned char*)OPENSSL_malloc(length);

	if (buffer == NULL)
	{
		printf("SSL_GC: out of memory\n");
		return 0;
	}

	switch (peer.sin_family) 
	{
		case AF_INET:
			memcpy(buffer, &peer.sin_port, sizeof(unsigned short));
			memcpy(buffer + sizeof(unsigned short), &peer.sin_addr, sizeof(struct in_addr));
			break;
		default:
			OPENSSL_assert(0);
			break;
	}

	/* Calculate HMAC of buffer using the secret */
	HMAC(EVP_sha1(), (const void*)cookie_secret, COOKIE_SECRET_LENGTH,
		(const unsigned char*)buffer, length, result, &resultlength);
	OPENSSL_free(buffer);

	if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
		return 1;

	return 0;
}
