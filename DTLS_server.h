
/*
 * Copyright (C) 2020 - 2021 Laidouni Habib, cyberpunkVx@gmail.com
 *				 2020 - 2021 DECIMA Technologies
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#pragma GCC diagnostic ignored "-fpermissive"

#pragma once
#ifndef DTLS_SERVER_H
#define DTLS_SERVER_H

#pragma comment (lib, "crypt32")

 /*	Net/Socket dependencies*/
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <vector>

/*	OpenSSL dependencies*/
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

#define COOKIE_SECRET_LENGTH 16

struct THREAD_ARG {
	struct sockaddr_in server_addr, client_addr;
	SSL* ssl;
	void* pInstance;
	#if WIN32
		DWORD tid;
	#else
		pthread_t tid;
	#endif
};

//GLOBALS
#if WIN32
	HANDLE* mutex_buf = NULL;
#else
	static pthread_mutex_t* __mutex_buf;
#endif

static unsigned char cookie_secret[COOKIE_SECRET_LENGTH];
static int cookie_initialized = 0;

class DTLS_SERVER
{
public:
	DTLS_SERVER();
	~DTLS_SERVER();

	virtual void setup_server(const char* server_ip_address, unsigned short server_port, bool verbosity);
	virtual void start_server();
	
public:
	bool verbose = false;
	char server_ip_addr[INET_ADDRSTRLEN] = { 0 };	//Server Ip Address
	unsigned short server_port = 0;
	bool stop_reception = false;					//Flag to stop reception	//Set this Flag to TRUE to STOP SERVER
private:
#if WIN32
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;
	SOCKET sock = INVALID_SOCKET;
#else
	int sock = NULL;
#endif

	struct sockaddr_in server_addr, client_addr;
	struct timeval timeout;
	SSL_CTX* ctx = nullptr;
	SSL* ssl = nullptr;
	BIO* bio = nullptr;
	std::vector<THREAD_ARG> thread_args;


	static void __CRYPTO_locking_function(int mode, int n, const char* file, int line);
	static unsigned long __CRYPTO_id_function(void);
	static int __OPENSSL_dtls_verify_callback(int ok, X509_STORE_CTX* ctx);
	static int __OPENSSL_generate_cookie(SSL* ssl, unsigned char* cookie, unsigned int* cookie_len);
	static int __OPENSSL_verify_cookie(SSL* ssl, unsigned char* cookie, unsigned int cookie_len);

	int __thread_prepare();
	int __thread_cleanup();

	virtual void __setup_socket();
	virtual void __start_listening();						//Enter reception Loop
	static void* __handle_client(void* thread_arg);			//Handle incoming connection

};

typedef void* (*THREADFUNCPTR)(void*);

#endif DTLS_SERVER_H