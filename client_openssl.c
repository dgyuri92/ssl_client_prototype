/**
 * Dead simple TLS client prototype with OpenSSL
 * GSoC 2014
 *
 * Author: György Demarcsek [sirius] <dgy.jr92@gmail.com>
 *
 * Tested: OpenSSL 1.0.1e, Debian (wheezy)
 * Example: client_openssl www.facebook.com 443
 * 
 * Mods:
 *  Added support for client authentication
**/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>
#include <getopt.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <openssl/opensslv.h> // only for OPENSSL_VERSION_NUMBER
#include <openssl/engine.h> // only for ENGINE_cleanup
#include <openssl/conf.h> // only for CONF_modules_free and CONF_modules_unload

#define MAX_PORT_LEN 5
#define MAX_PW_LEN 4096
#define MAX_HOSTNAME_LEN 256
#define DATA_BUFSIZE 1024
#define DN_CN_MAX_LEN 256
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define ERR_HANDLER \
		ERR_print_errors_fp(stderr); \
		close_all(channel, ctx); \
		exit(ERR_peek_last_error());

#define DEFAULT_PORT "443"

// User input
char target_port[MAX_PORT_LEN];
char target_server[MAX_HOSTNAME_LEN];
char ca_file_path[PATH_MAX];
char cert_file_path[PATH_MAX];
char key_file_path[PATH_MAX];
char key_password[MAX_PW_LEN];
// Socket buffer
char data_buffer[DATA_BUFSIZE];

void usage(char* exec);
int verify_cert(SSL* conn);
void libc_critical(int errcode, const char* pstr);
void print_x509_certificate_info(BIO* bio, SSL* s);
int print_conn_info(BIO* bio, SSL* s);
void close_all(BIO* bio, SSL_CTX* ctx);
void hex_dump(char *desc, void *addr, int len);


int main(int argc, char* argv[]) {
    if (argc < 2)
		usage(argv[0]);
	
    bzero(ca_file_path, PATH_MAX);
    bzero(cert_file_path, PATH_MAX);
    bzero(key_file_path, PATH_MAX);
    bzero(key_password, MAX_PW_LEN);

    static int verbose = 0;
    static struct option cmd_opts[] = {
        {"verbose", no_argument, &verbose, 1},
        {"ca", required_argument, 0, 'a'},
        {"cert", required_argument, 0, 'c'},
        {"key", required_argument, 0, 'k'},
        {"pw", required_argument, 0, 'p'},
        {0,0,0,0}
    };

	int c, oi = 0;
    while (1) {
        if ((c = getopt_long(argc, argv, "a:c:k:p:", cmd_opts, &oi)) == -1) break;
        switch (c) {
            case '0':
            case '?':
                break;
            case 'a':
                strncpy(ca_file_path, optarg, PATH_MAX);
                break;
            case 'c':
                strncpy(cert_file_path, optarg, PATH_MAX);
                break;
            case 'k':
                strncpy(key_file_path, optarg, PATH_MAX);
                break;
            case 'p':
                strncpy(key_password, optarg, MAX_PW_LEN);
                break;
            default:
                break;
        }
    }

    if (optind < argc) {
        strncpy(target_server, argv[optind++], MAX_HOSTNAME_LEN);
        if (optind < argc) {
            strncpy(target_port, argv[optind++], MAX_PORT_LEN);
        } else {
            strcpy(target_port, DEFAULT_PORT);
        }
    }
    
    const char* accepted_ciphers = "HIGH";	// all compiled high security algorithms (ECDHE,RSA,AES,SHA256,..)
	SSL_CTX* ctx = NULL;
	SSL* conn = NULL;
	int err = 1;
	BIO* channel = NULL;
	char tmp[MAX_HOSTNAME_LEN + MAX_PORT_LEN];
	BIO* _bio_stdout = BIO_new_fp(stdout, BIO_NOCLOSE);
	int bytes_recv = 0;
    int bytes_sent = 0;

	CRYPTO_malloc_init();
	OPENSSL_config(NULL);
	SSL_load_error_strings();
	ERR_load_BIO_strings();
	SSL_library_init();
	
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
        ERR_HANDLER;
	}
	
	SSL_CTX_set_options(
		ctx, 
		SSL_OP_NO_SSLv2 | 			// Do not support SSL 2 (insecure)
		SSL_OP_NO_COMPRESSION | 	// Turn off compression (BREACH / CRIME attacks)
		SSL_OP_ALL |				// Require remote peer to have bug fixes (see OpenSSL man page)
		SSL_OP_SINGLE_DH_USE |		// Extra DH/EC security options
		SSL_OP_EPHEMERAL_RSA
	);
	
	// Set the list of client accepted ciphers
	if (SSL_CTX_set_cipher_list(ctx, accepted_ciphers) != 1) {
		ERR_HANDLER;
	}

    if (strlen(ca_file_path) != 0) {
        // Try to specify user-given CA cert file (PEM format)
        if (!SSL_CTX_load_verify_locations(ctx, ca_file_path, NULL)) {
            ERR_HANDLER;
        }
    } else {
	    // Try to set up environment default trusted CA certs path, etc.
	    if (!SSL_CTX_set_default_verify_paths(ctx)) {
		    ERR_HANDLER;
	    }
    }

    // Set up client certificate
    if (strlen(cert_file_path) != 0) {
        if (!SSL_CTX_use_certificate_file(ctx, cert_file_path, SSL_FILETYPE_PEM)) {
            ERR_HANDLER;
        }
    }

    // Set up client private key
    if (strlen(key_file_path) != 0) {
        if (strlen(key_password) == 0) { // Assuming unencrypted private keys
            if (!SSL_CTX_use_PrivateKey_file(ctx, key_file_path, SSL_FILETYPE_PEM)) {
                ERR_HANDLER;
            }
            if (!SSL_CTX_check_private_key(ctx)) {
                ERR_HANDLER;
            }
        } else {
            FILE* pKeyFile = fopen(key_file_path, "r");
            if (pKeyFile == NULL) {
                fprintf(stderr, "%s\n", "Unable to open key file");
                ERR_HANDLER;
            }
            EVP_PKEY* private_key = PEM_read_PrivateKey(pKeyFile, NULL, NULL, key_password);
            bzero(key_password, MAX_PW_LEN);
            if (private_key == NULL) {
                ERR_HANDLER;
            }
            if (!SSL_CTX_use_PrivateKey(ctx, private_key)) {
                ERR_HANDLER;
            }
            fclose(pKeyFile);
        }
    }

	// Set up trust chain verification depth
	SSL_CTX_set_verify_depth(ctx, 5);
	
	// BIO channel setup
	channel = BIO_new_ssl_connect(ctx);
	BIO_get_ssl(channel, &conn);

	if (conn == NULL) {
		ERR_print_errors_fp(stderr);
		close_all(channel, ctx);
		exit(ERR_peek_last_error());
	}

	// Enable auto-retry mode
	SSL_set_mode(conn, SSL_MODE_AUTO_RETRY);

	// Set server hostname for SNI
	if (!SSL_set_tlsext_host_name(conn, target_server)) {
		ERR_print_errors_fp(stderr);
		close_all(channel, ctx);
		exit(ERR_peek_last_error());
	}

    printf("Target: %s:%s\n", target_server, target_port);
	sprintf(tmp, "%s:%s", target_server, target_port);
	BIO_set_conn_hostname(channel, tmp);

	//SSL_set_tlsext_status_type(conn, TLSEXT_STATUSTYPE_ocsp);
	
	printf("Connecting...\n");

	if (BIO_do_connect(channel) <= 0) {
		ERR_HANDLER;
	}

	printf("Client HELLO (performing handshake...)\n");

	// perform handshake
	if (BIO_do_handshake(channel) <= 0) {
		ERR_HANDLER;
	}

	if (verify_cert(conn) != 1) {
		fprintf(stderr, "Invalid certificate\n");
		close_all(channel, ctx);
		exit(1);
	}

	if (verbose) print_conn_info(_bio_stdout, conn);

    printf("Message:");
    while ( ((c = fgetc(stdin)) != EOF) && (bytes_sent < DATA_BUFSIZE) ) {
        data_buffer[bytes_sent++] = c;
    }

	//fgets(data_buffer, DATA_BUFSIZE - 5, stdin);
	//strcat(data_buffer, "\r\n\r\n");		// Append CRLFs (e.g. HTTP servers like it:))

	//err = BIO_puts(channel, data_buffer);
	
    err = BIO_write(channel, data_buffer, bytes_sent);

	if (err <= 0) {
		ERR_HANDLER;
	} 
    
    printf("%d byte(s) written\n", err);

    if (err != bytes_sent) {
        fprintf(stderr, "%s\n", "It seems that not all data has been sent successfully :(");
    }

	printf("Recieving reply...\n\n");

	do {
		err = BIO_read(channel, data_buffer, DATA_BUFSIZE);
		bytes_recv += err;
		hex_dump("reply", data_buffer, bytes_recv);
	} while(BIO_should_read(channel));
	
	if (err < 0) {
		ERR_HANDLER;
	}
	
	printf("\n%d byte(s) read\n", bytes_recv);

	printf("Data recieved.\n");
	
	printf("Client BYE\n");

	close_all(channel, ctx);
	return EXIT_SUCCESS;
}

/**
 * Verifies the server certificate in the given connection
**/
int verify_cert(SSL* conn) {
	if (conn == NULL) return -1;
	char srv_cn[DN_CN_MAX_LEN];
	X509* cert;
	int err = 1;
	char* p1, *p2; char* s1, *s2;	// used for tokenizing CN-s
	int ret = 1;
	struct in_addr tmp;
	
	cert = SSL_get_peer_certificate(conn);

	if (cert == NULL) {
		fprintf(stderr, "Certificate seems to be missing\n");
		ret = -1;
	}

	err = SSL_get_verify_result(conn);
	
	if (err != X509_V_OK) {
		fprintf(stderr, "Certificate validation failed: %s\n", X509_verify_cert_error_string(err));
		ret = -1;
	}

	if (inet_pton(AF_INET, target_server, &tmp) <= 0) {	// not an IP address
		#if OPENSSL_VERSION_NUMBER >= 0x010100000 // Only available in OpenSSL 1.1 and above
		if (X509_check_host(cert, (unsigned char*) target_server, strlen(target_server), 0) != 1) {
			fprintf(stderr, "SNI mismatch\n");
			ret = -1;
		}
		#else // Simple, manual host name check
		X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, srv_cn, DN_CN_MAX_LEN);
		p1 = strtok_r(srv_cn, ".", &s1);
		p2 = strtok_r(target_server, ".", &s2);
		while ( (p1 != NULL) && (p2 != NULL) ) {
			if (p1[0] != '*') {
				if (strcasecmp(p1, p2) != 0) {
					ret = -1;
					fprintf(stderr, "SNI mismatch : (%s) != (%s)\n", p1, p2);
					break;
				}
			}
			p1 = strtok_r(NULL, ".", &s1);
			p2 = strtok_r(NULL, ".", &s2);
		}
		#endif
	}
	
	if (cert != NULL)
		X509_free(cert);
	
	return ret;
}

/**
 * OpenSSL library cleanup (reduces OpenSSL-related memory leaks)
**/
void lib_cleanup() {
	CONF_modules_free();	// config cleanup
	ERR_remove_state(0);	// free error queue
	ENGINE_cleanup();		// internal crypto engine cleanup
	CONF_modules_unload(1);	// unloading each conf modules
	ERR_free_strings();	// free error strings
	EVP_cleanup();		// just in case (EVP is not really used by this code)
	CRYPTO_cleanup_all_ex_data();
}

/**
 * Resets the connection (ClientFinish), deallocates BIOs, CTX-es and internal OpenSSL memory structures. 
 * Please note, that this function is not reentrant - exit() should be called afterwards!
**/
void close_all(BIO* bio, SSL_CTX* ctx) {
	if (bio != NULL) BIO_reset(bio);
	if (bio != NULL) BIO_free_all(bio);
	if (ctx != NULL) SSL_CTX_free(ctx);
	lib_cleanup();
}

/**
 * Displays X.509 certificate details. (In case there's a different type of cert used in the session, 
 * it does not print details)
**/
void print_x509_certificate_info(BIO* bio, SSL* s) {
	X509 *peer = NULL;
	char namebuf[DN_CN_MAX_LEN];
	STACK_OF(X509) *sk;
	unsigned int cert_list_size = 0;

	sk = SSL_get_peer_cert_chain(s);
	if (sk != NULL) {
		BIO_printf(bio, "-= Certificate information =- \n");
		cert_list_size = sk_X509_num(sk);
		BIO_printf(bio, "- %d certificate(s) in chain\n", cert_list_size);

		BIO_printf(bio,"---\n");
		peer = SSL_get_peer_certificate(s);
		if ((peer != NULL) && (cert_list_size > 0)) {
			BIO_printf(bio,"!Cert\n");
			X509_NAME_oneline(X509_get_subject_name(peer), namebuf, sizeof(namebuf));
			BIO_printf(bio,"- Subject: %s\n", namebuf);
			X509_NAME_oneline(X509_get_issuer_name(peer), namebuf, sizeof(namebuf));
			BIO_printf(bio,"- Issuer: %s\n", namebuf);
		} else {
			BIO_printf(bio,"- NO CERTIFICATE AVAILABLE\n");
		}
	
	} else {
		BIO_printf(bio, "- Unable to read certificate chain\n");
	}
	
	if (peer != NULL) {
		EVP_PKEY *pktmp;
		pktmp = X509_get_pubkey(peer);
		int type = EVP_PKEY_type(pktmp->type);
		char pkey_type[4];
		switch(type) {
			case EVP_PKEY_RSA: strcpy(pkey_type, "RSA"); break;
			case EVP_PKEY_DSA: strcpy(pkey_type, "DSA"); break;
			case EVP_PKEY_DH:  strcpy(pkey_type, "DH"); break;
			case EVP_PKEY_EC:  strcpy(pkey_type, "EC"); break;
			default: strcpy(pkey_type, "??");
		}
		BIO_printf(bio, "- Public key type: %s (%d bits)\n", pkey_type, EVP_PKEY_bits(pktmp));
		EVP_PKEY_free(pktmp);
	}
	
	BIO_printf(bio,"\n");
	if (peer != NULL)
		X509_free(peer);
}

/**
 * Prints useful session information to the user
**/
int print_conn_info(BIO* bio, SSL* s) {
	if (bio == NULL || s == NULL) return 0;
	printf("-= Connection information =- \n");
	BIO_printf(bio, "--\n");
	SSL_SESSION_print(bio, SSL_get_session(s));
	print_x509_certificate_info(bio, s);
	BIO_flush(bio);
	return 1;
}


/**
 * Command line usage help
**/
void usage(char* exec) {
	printf("Simple SSL client prototype by György Demarcsek\n");
    printf("Usage: %s [OPTIONS] <hostname> [<port>]\n", exec);
    printf("Available OPTIONS:\n");
    printf("  --ca <path>   : Specify CA cert file path (PEM formatted, using OpenSSL built-ins if absorbed)\n");
    printf("  --cert <path> : Specify client cert file path (PEM formatted, used for mutual authentication)\n");
    printf("  --key <path>  : Specify client key file path (PEM formatted private key)\n");
    printf("  --pw <pass>   : Specify password for encrypted key file\n");
    printf("  --verbose     : Print connection & certificate information\n");
	printf("Default port is %s\n", DEFAULT_PORT);
    exit(1);
}

/**
 * Hex dump (desc - description, addr - address of memory to dump, len - length of data)
 * Origin: http://stackoverflow.com/questions/7775991/how-to-get-hexdump-of-a-structure-data
**/
void hex_dump(char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char*)addr;

    // Output description if given.
    if (desc != NULL)
        printf ("%s:\n", desc);

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf ("  %s\n", buff);

            // Output the offset.
            printf ("  %04x -", i);
        }

        // Now the hex code for the specific character.
        printf (" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf ("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf ("  %s\n", buff);
}
