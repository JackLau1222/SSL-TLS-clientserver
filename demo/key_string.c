#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdlib.h>

/**
 * Deserialize a PEM‐encoded private or public key from a NUL-terminated C string.
 *
 * @param pem_str   The PEM text, e.g.
 *                  "-----BEGIN PRIVATE KEY-----\n…\n-----END PRIVATE KEY-----\n"
 * @param is_priv   If non-zero, parse as a PRIVATE key; otherwise, parse as a PUBLIC key.
 * @return          EVP_PKEY* on success (must EVP_PKEY_free()), or NULL on error.
 */
EVP_PKEY *pkey_from_pem_string(const char *pem_str, int is_priv)
{
    BIO *mem = BIO_new_mem_buf(pem_str, -1);
    if (!mem) {
        fprintf(stderr, "BIO_new_mem_buf failed\n");
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (is_priv) {
        pkey = PEM_read_bio_PrivateKey(mem, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    }

    if (!pkey) {
        fprintf(stderr, "Failed to parse %s key from string\n",
                is_priv ? "private" : "public");
    }

    BIO_free(mem);
    return pkey;
}

/**
 * Deserialize a PEM‐encoded certificate from a NUL-terminated C string.
 *
 * @param pem_str   The PEM text, e.g.
 *                  "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n"
 * @return          X509* on success (must X509_free()), or NULL on error.
 */
X509 *cert_from_pem_string(const char *pem_str)
{
    BIO *mem = BIO_new_mem_buf(pem_str, -1);
    if (!mem) {
        fprintf(stderr, "BIO_new_mem_buf failed\n");
        return NULL;
    }

    X509 *cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Failed to parse certificate from string\n");
    }

    BIO_free(mem);
    return cert;
}


// Returns a heap‐allocated null‐terminated string containing
// the PEM‐encoded public key.  Caller must free().
char *evp_pkey_to_pem_string(EVP_PKEY *pkey) {
    BIO        *mem = NULL;
    BUF_MEM    *bptr = NULL;
    char       *pem_str = NULL;

    // 1) Create a memory BIO
    if ((mem = BIO_new(BIO_s_mem())) == NULL)
        goto err;

    // 2) Write public key in PEM form
    if (!PEM_write_bio_PrivateKey(mem, pkey, NULL, NULL, 0, NULL, NULL))
        goto err;

    // 3) Extract pointer/length
    BIO_get_mem_ptr(mem, &bptr);
    if (bptr == NULL || bptr->length == 0)
        goto err;

    // 4) Allocate string (+1 for NUL)
    pem_str = malloc(bptr->length + 1);
    if (pem_str == NULL)
        goto err;

    // 5) Copy data & NUL‐terminate
    memcpy(pem_str, bptr->data, bptr->length);
    pem_str[bptr->length] = '\0';

cleanup:
    BIO_free(mem);
    return pem_str;

err:
    // error path: free and return NULL
    free(pem_str);
    pem_str = NULL;
    goto cleanup;
}

/**
 * Load an EVP_PKEY from a local “file://” URL (or plain path).
 *
 * @param url     A UTF-8 string of the form "file:///absolute/path/to/key.pem"
 *                or simply "/absolute/path/to/key.pem".
 * @param is_priv If non-zero, read a private key; otherwise, read a public key.
 * @return        EVP_PKEY* on success (must EVP_PKEY_free()), NULL on error.
 */
EVP_PKEY *load_key_from_file_url(const char *url, int is_priv)
{
    const char *path = url;

    // 1) Strip off leading "file://" if present
    if (strncmp(url, "file://", 7) == 0) {
        path = url + 7;
        // On POSIX, file URLs are file:///foo → path=="/foo"
        if (*path == '/' && *(path+1) == '/')
            path++;  // skip extra slash so "///foo" → "/foo"
    }

    // 2) Open it as a BIO
    BIO *bio = BIO_new_file(path, "r");
    if (!bio) {
        fprintf(stderr, "Error opening key file \"%s\"\n", path);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;

    // 3) Read in PEM (or DER, if you prefer) form
    if (is_priv) {
        // Reads unencrypted PEM private key:
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        // If you need to handle passphrase, supply passwd_cb or a password.
    } else {
        // Reads PEM public key (SubjectPublicKeyInfo)
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }

    if (!pkey) {
        fprintf(stderr, "Error parsing %s key from \"%s\"\n",
                is_priv ? "private" : "public", path);
    }

    BIO_free(bio);
    return pkey;
}

/**
 * Load an X509 certificate from a local “file://” URL (or plain path).
 * Returns a freshly-allocated X509*, or NULL on error.
 * Caller must call X509_free().
 */
X509 *load_cert_from_file(const char *url)
{
    const char *path = url;
    if (strncmp(url, "file://", 7) == 0) {
        path = url + 7;
        if (*path == '/' && *(path+1) == '/')
            path++;
    }

    BIO *bio = BIO_new_file(path, "r");
    if (!bio) {
        fprintf(stderr, "Error opening cert file %s\n", path);
        return NULL;
    }

    /* Read the PEM certificate (PEM_read_bio_X509 reads a Subject:… block) */
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    if (!cert) {
        fprintf(stderr, "Error parsing certificate from %s\n", path);
    }

    BIO_free(bio);
    return cert;
}

/**
 * Serialize an X509 certificate to a malloc’d PEM string.
 * Caller must free() the returned pointer.
 */
char *cert_to_pem_string(X509 *cert)
{
    BIO     *mem = BIO_new(BIO_s_mem());
    BUF_MEM *bptr = NULL;
    char    *out = NULL;

    if (!mem) goto err;

    /* Write the PEM certificate */
    if (!PEM_write_bio_X509(mem, cert))
        goto err;

    BIO_get_mem_ptr(mem, &bptr);
    if (!bptr || bptr->length == 0) goto err;

    out = malloc(bptr->length + 1);
    if (!out) goto err;

    memcpy(out, bptr->data, bptr->length);
    out[bptr->length] = '\0';

cleanup:
    BIO_free(mem);
    return out;

err:
    free(out);
    out = NULL;
    goto cleanup;
}

int main()
{
    // Suppose your key is at “file:///home/alice/keys/mykey.pem”
    const char *url = "file:///Users/jacklau/Documents/Programs/Git/Github/SSL-TLS-clientserver/cert/server-key.pem";

    // Load as private key:
    EVP_PKEY *priv = load_key_from_file_url(url, 1);
    if (!priv) return 1;

    char *priv_pem = EVP_PKEY_to_PEM_string(priv);
    if (priv_pem) {
        // printf("My key is:\n%s\n", priv_pem);
    }

    const char *cert_url = "file:///Users/jacklau/Documents/Programs/Git/Github/SSL-TLS-clientserver/cert/server-cert.pem";

    X509 *cert = load_cert_from_file(cert_url);
    if (!cert) return 1;

    char *cert_pem = cert_to_pem_string(cert);
    if (cert_pem) {
        // printf("Certificate:\n%s\n", cert_pem);
    }

    EVP_PKEY *priv_tem = pkey_from_pem_string(priv_pem, 1);
    if (priv_tem) {
        printf("Loaded private key!\n");
        priv_pem = EVP_PKEY_to_PEM_string(priv_tem);
        if (priv_pem) {
            printf("Private key PEM:\n%s\n", priv_pem);
        }
    }

    X509 *cert_tem = cert_from_pem_string(cert_pem);
    if (cert_tem) {
        printf("Loaded X509 certificate!\n");       
        cert_pem = cert_to_pem_string(cert_tem);
        if (cert_pem) {
            printf("Certificate PEM:\n%s\n", cert_pem);
        }
    }

    X509_free(cert);
    free(priv_pem);
    free(cert_pem);
    EVP_PKEY_free(priv_tem);
    X509_free(cert_tem);

    return 0;
}