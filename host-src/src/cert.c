/* Self-signed TLS certificate, generated with CNG and cached as a .pfx.
 *
 * Regenerated automatically whenever it stops matching the current IP or
 * domain list, so moving the exe between machines just works - the same
 * behaviour the Python build had, without the cryptography package.
 */
#include "host.h"
#include <wincrypt.h>
#include <ncrypt.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PFX_NAME   "snakeoil.pfx"
#define KEY_NAME   L"ps-exploit-host-tls"
#define VALID_DAYS 3650

static LPWSTR widen(const char *s)
{
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    LPWSTR w = (LPWSTR)malloc(n * sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, s, -1, w, n);
    return w;
}

/* ------------------------------------------------------------- validation */

static int san_covers(PCCERT_CONTEXT cert, const char *ip,
                      char *const *domains, int n)
{
    PCERT_EXTENSION ext;
    CERT_ALT_NAME_INFO *alt = NULL;
    DWORD len = 0;
    DWORD want_ip = inet_addr(ip);
    int ok = 1, i, j;

    ext = CertFindExtension(szOID_SUBJECT_ALT_NAME2,
                            cert->pCertInfo->cExtension,
                            cert->pCertInfo->rgExtension);
    if (!ext)
        return 0;

    if (!CryptDecodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME,
                             ext->Value.pbData, ext->Value.cbData,
                             CRYPT_DECODE_ALLOC_FLAG, NULL, &alt, &len))
        return 0;

    /* the IP must be present, or Schannel offers a cert for the wrong host */
    ok = 0;
    for (i = 0; i < (int)alt->cAltEntry; i++) {
        CERT_ALT_NAME_ENTRY *e = &alt->rgAltEntry[i];
        if (e->dwAltNameChoice == CERT_ALT_NAME_IP_ADDRESS &&
            e->IPAddress.cbData == 4 &&
            memcmp(e->IPAddress.pbData, &want_ip, 4) == 0) {
            ok = 1;
            break;
        }
    }

    for (j = 0; ok && j < n; j++) {
        LPWSTR w = widen(domains[j]);
        int found = 0;
        for (i = 0; i < (int)alt->cAltEntry; i++) {
            CERT_ALT_NAME_ENTRY *e = &alt->rgAltEntry[i];
            if (e->dwAltNameChoice == CERT_ALT_NAME_DNS_NAME &&
                _wcsicmp(e->pwszDNSName, w) == 0) {
                found = 1;
                break;
            }
        }
        free(w);
        if (!found) {
            log_line("[TLS]  existing cert is missing %s", domains[j]);
            ok = 0;
        }
    }

    LocalFree(alt);
    return ok;
}

static int not_expired(PCCERT_CONTEXT cert)
{
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    if (CompareFileTime(&now, &cert->pCertInfo->NotAfter) >= 0) {
        log_line("[TLS]  existing cert has expired");
        return 0;
    }
    return 1;
}

/* ------------------------------------------------------------ pfx storage */

static PCCERT_CONTEXT load_pfx(const char *path)
{
    HANDLE f;
    DWORD size, got;
    unsigned char *buf;
    CRYPT_DATA_BLOB blob;
    HCERTSTORE store;
    PCCERT_CONTEXT cert;

    f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return NULL;

    size = GetFileSize(f, NULL);
    if (size == INVALID_FILE_SIZE || size == 0 || size > 1024 * 1024) {
        CloseHandle(f);
        return NULL;
    }
    buf = (unsigned char *)malloc(size);
    if (!ReadFile(f, buf, size, &got, NULL) || got != size) {
        free(buf);
        CloseHandle(f);
        return NULL;
    }
    CloseHandle(f);

    blob.cbData = size;
    blob.pbData = buf;
    store = PFXImportCertStore(&blob, L"", CRYPT_EXPORTABLE | CRYPT_USER_KEYSET);
    free(buf);
    if (!store)
        return NULL;

    cert = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0,
                                      CERT_FIND_ANY, NULL, NULL);
    CertCloseStore(store, 0);
    return cert;
}

static int save_pfx(PCCERT_CONTEXT cert, const char *path)
{
    HCERTSTORE store;
    CRYPT_DATA_BLOB blob;
    HANDLE f;
    DWORD wrote;
    int ok = 0;

    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0,
                          CERT_STORE_CREATE_NEW_FLAG, NULL);
    if (!store)
        return 0;
    if (!CertAddCertificateContextToStore(store, cert,
                                          CERT_STORE_ADD_ALWAYS, NULL))
        goto out;

    memset(&blob, 0, sizeof(blob));
    if (!PFXExportCertStoreEx(store, &blob, L"", NULL,
                              EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY))
        goto out;
    blob.pbData = (BYTE *)malloc(blob.cbData);
    if (!PFXExportCertStoreEx(store, &blob, L"", NULL,
                              EXPORT_PRIVATE_KEYS | REPORT_NO_PRIVATE_KEY)) {
        free(blob.pbData);
        goto out;
    }

    f = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        ok = WriteFile(f, blob.pbData, blob.cbData, &wrote, NULL) &&
             wrote == blob.cbData;
        CloseHandle(f);
    }
    free(blob.pbData);

out:
    CertCloseStore(store, 0);
    return ok;
}

/* ------------------------------------------------------------- generation */

static NCRYPT_KEY_HANDLE make_key(void)
{
    NCRYPT_PROV_HANDLE prov = 0;
    NCRYPT_KEY_HANDLE key = 0;
    DWORD bits = 2048;
    DWORD policy = NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

    if (NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS)
        return 0;

    if (NCryptCreatePersistedKey(prov, &key, NCRYPT_RSA_ALGORITHM, KEY_NAME, 0,
                                 NCRYPT_OVERWRITE_KEY_FLAG) != ERROR_SUCCESS) {
        NCryptFreeObject(prov);
        return 0;
    }
    NCryptSetProperty(key, NCRYPT_LENGTH_PROPERTY, (PBYTE)&bits, sizeof(bits), 0);
    /* exportable, otherwise the .pfx cache cannot be written */
    NCryptSetProperty(key, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&policy,
                      sizeof(policy), 0);

    if (NCryptFinalizeKey(key, 0) != ERROR_SUCCESS) {
        NCryptFreeObject(key);
        NCryptFreeObject(prov);
        return 0;
    }
    NCryptFreeObject(prov);
    return key;
}

static int build_san(const char *ip, char *const *domains, int n,
                     CERT_EXTENSION *out)
{
    CERT_ALT_NAME_INFO info;
    CERT_ALT_NAME_ENTRY *ents;
    DWORD want_ip = inet_addr(ip);
    int count = 0, i;
    BYTE *enc = NULL;
    DWORD enclen = 0;

    /* every domain, its wildcard, plus the raw IP */
    ents = (CERT_ALT_NAME_ENTRY *)calloc(n * 2 + 1, sizeof(CERT_ALT_NAME_ENTRY));
    for (i = 0; i < n; i++) {
        char star[300];
        ents[count].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
        ents[count].pwszDNSName = widen(domains[i]);
        count++;
        snprintf(star, sizeof(star), "*.%s", domains[i]);
        ents[count].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
        ents[count].pwszDNSName = widen(star);
        count++;
    }
    ents[count].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
    ents[count].IPAddress.cbData = 4;
    ents[count].IPAddress.pbData = (BYTE *)malloc(4);
    memcpy(ents[count].IPAddress.pbData, &want_ip, 4);
    count++;

    info.cAltEntry = count;
    info.rgAltEntry = ents;

    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &info,
                             CRYPT_ENCODE_ALLOC_FLAG, NULL, &enc, &enclen)) {
        for (i = 0; i < count; i++)
            if (ents[i].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME)
                free(ents[i].pwszDNSName);
            else
                free(ents[i].IPAddress.pbData);
        free(ents);
        return 0;
    }

    for (i = 0; i < count; i++)
        if (ents[i].dwAltNameChoice == CERT_ALT_NAME_DNS_NAME)
            free(ents[i].pwszDNSName);
        else
            free(ents[i].IPAddress.pbData);
    free(ents);

    out->pszObjId = (LPSTR)szOID_SUBJECT_ALT_NAME2;
    out->fCritical = FALSE;
    out->Value.cbData = enclen;
    out->Value.pbData = enc;
    return 1;
}

static PCCERT_CONTEXT generate(const char *ip, char *const *domains, int n)
{
    NCRYPT_KEY_HANDLE key;
    CRYPT_KEY_PROV_INFO kpi;
    CRYPT_ALGORITHM_IDENTIFIER algo;
    CERT_EXTENSION exts[3];
    CERT_EXTENSIONS extensions;
    CERT_NAME_BLOB subject;
    CERT_BASIC_CONSTRAINTS2_INFO bc;
    CERT_ENHKEY_USAGE eku;
    LPSTR eku_oid = (LPSTR)szOID_PKIX_KP_SERVER_AUTH;
    BYTE *bc_enc = NULL, *eku_enc = NULL;
    DWORD bc_len = 0, eku_len = 0, name_len = 0;
    char subj[512];
    SYSTEMTIME st_start, st_end;
    FILETIME ft;
    ULARGE_INTEGER ui;
    PCCERT_CONTEXT cert = NULL;
    int nexts = 0, i;

    key = make_key();
    if (!key) {
        log_line("[TLS]  CNG key generation failed (err %lu)", GetLastError());
        return NULL;
    }

    snprintf(subj, sizeof(subj),
             "CN=%s, O=Sony Interactive Entertainment", domains[0]);
    if (!CertStrToNameA(X509_ASN_ENCODING, subj, CERT_X500_NAME_STR, NULL,
                        NULL, &name_len, NULL))
        goto out;
    subject.pbData = (BYTE *)malloc(name_len);
    subject.cbData = name_len;
    if (!CertStrToNameA(X509_ASN_ENCODING, subj, CERT_X500_NAME_STR, NULL,
                        subject.pbData, &name_len, NULL))
        goto out;
    subject.cbData = name_len;

    if (!build_san(ip, domains, n, &exts[nexts]))
        goto out;
    nexts++;

    memset(&bc, 0, sizeof(bc));
    bc.fCA = TRUE;                        /* self-signed root for itself */
    if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_BASIC_CONSTRAINTS2, &bc,
                            CRYPT_ENCODE_ALLOC_FLAG, NULL, &bc_enc, &bc_len)) {
        exts[nexts].pszObjId = (LPSTR)szOID_BASIC_CONSTRAINTS2;
        exts[nexts].fCritical = TRUE;
        exts[nexts].Value.cbData = bc_len;
        exts[nexts].Value.pbData = bc_enc;
        nexts++;
    }

    eku.cUsageIdentifier = 1;
    eku.rgpszUsageIdentifier = &eku_oid;
    if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &eku,
                            CRYPT_ENCODE_ALLOC_FLAG, NULL, &eku_enc, &eku_len)) {
        exts[nexts].pszObjId = (LPSTR)szOID_ENHANCED_KEY_USAGE;
        exts[nexts].fCritical = FALSE;
        exts[nexts].Value.cbData = eku_len;
        exts[nexts].Value.pbData = eku_enc;
        nexts++;
    }

    extensions.cExtension = nexts;
    extensions.rgExtension = exts;

    memset(&kpi, 0, sizeof(kpi));
    kpi.pwszContainerName = (LPWSTR)KEY_NAME;
    kpi.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
    kpi.dwProvType = 0;                   /* CNG */
    kpi.dwKeySpec = 0;

    memset(&algo, 0, sizeof(algo));
    algo.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;

    GetSystemTime(&st_start);
    SystemTimeToFileTime(&st_start, &ft);
    ui.LowPart = ft.dwLowDateTime;
    ui.HighPart = ft.dwHighDateTime;
    ui.QuadPart -= 864000000000ULL;                    /* backdate one day */
    ft.dwLowDateTime = ui.LowPart;
    ft.dwHighDateTime = ui.HighPart;
    FileTimeToSystemTime(&ft, &st_start);

    ui.QuadPart += (ULONGLONG)VALID_DAYS * 864000000000ULL;
    ft.dwLowDateTime = ui.LowPart;
    ft.dwHighDateTime = ui.HighPart;
    FileTimeToSystemTime(&ft, &st_end);

    cert = CertCreateSelfSignCertificate((ULONG_PTR)NULL, &subject, 0, &kpi,
                                         &algo, &st_start, &st_end, &extensions);
    if (!cert)
        log_line("[TLS]  CertCreateSelfSignCertificate failed (err %lu)",
                 GetLastError());

out:
    for (i = 0; i < nexts; i++)
        if (exts[i].Value.pbData)
            LocalFree(exts[i].Value.pbData);
    NCryptFreeObject(key);
    return cert;
}

/* ---------------------------------------------------------------- entry */

int cert_ensure(const char *dir, const char *ip, char *const *domains, int n,
                PCCERT_CONTEXT *out)
{
    char path[MAX_PATH];
    PCCERT_CONTEXT cert;

    snprintf(path, sizeof(path), "%s\\%s", dir, PFX_NAME);

    cert = load_pfx(path);
    if (cert) {
        if (not_expired(cert) && san_covers(cert, ip, domains, n)) {
            *out = cert;
            return 1;
        }
        log_line("[TLS]  regenerating certificate for %s", ip);
        CertFreeCertificateContext(cert);
    }

    cert = generate(ip, domains, n);
    if (!cert)
        return 0;

    if (!save_pfx(cert, path))
        log_line("[TLS]  note: could not cache %s (will regenerate next run)",
                 PFX_NAME);

    log_line("[TLS]  self-signed cert ready: %s + %d domain(s)", ip, n);
    *out = cert;
    return 1;
}
