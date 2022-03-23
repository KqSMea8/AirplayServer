#ifndef DNSSD_H
#define DNSSD_H

#if defined(WIN32) && defined(DLL_EXPORT)
# define DNSSD_API __declspec(dllexport)
#else
# define DNSSD_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define DNSSD_ERROR_NOERROR       0
#define DNSSD_ERROR_HWADDRLEN     1
#define DNSSD_ERROR_OUTOFMEM      2
#define DNSSD_ERROR_LIBNOTFOUND   3
#define DNSSD_ERROR_PROCNOTFOUND  4

typedef struct dnssd_s dnssd_t;

DNSSD_API dnssd_t *dnssd_init(const char *name, int name_len, const char *hw_addr, int hw_addr_len, int *error);

DNSSD_API int dnssd_register_raop(dnssd_t *dnssd, unsigned short port);
DNSSD_API int dnssd_register_airplay(dnssd_t *dnssd, unsigned short port);

DNSSD_API void dnssd_unregister_raop(dnssd_t *dnssd);
DNSSD_API void dnssd_unregister_airplay(dnssd_t *dnssd);

DNSSD_API const char *dnssd_get_airplay_txt(dnssd_t *dnssd, int *length);
DNSSD_API const char *dnssd_get_name(dnssd_t *dnssd, int *length);
DNSSD_API const char *dnssd_get_hw_addr(dnssd_t *dnssd, int *length);

DNSSD_API void dnssd_destroy(dnssd_t *dnssd);

#ifdef __cplusplus
}
#endif
#endif