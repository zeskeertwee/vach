#pragma once

#include <stdbool>

// The length of the magic string in the file header
#define V_MAGIC_LENGTH 5

// The length of a public key
#define V_PUBLIC_KEY_LENGTH 32

// One parameter passed to a function was NULL
#define E_PARAMETER_IS_NULL -1

// Unable to parse a key or signature
#define E_PARSE_ERROR -2

// String parameter was not valid UTF8 sequence
#define E_INVALID_UTF8 -3

// Generic IO error
#define E_GENERIC_IO_ERROR -4

// Malformed archive source, invalid MAGIC or otherwise
#define E_MALFORMED_ARCHIVE_SOURCE -5

// Resource not found
#define E_RESOURCE_NOT_FOUND -6

// Unknown error
#define E_UNKNOWN -7

// One or more necessary library features wasn't enabled during compilation
#define E_MISSING_FEATURE_ERROR -8

// Generic cryptographic error, signature verification failed or otherwise
#define E_CRYPTO_ERROR -9

// Archive loader configuration
typedef char v_archive_config;

// An Archive instance, bound to either a file or a buffer
typedef unsigned char v_archive;

// A list archive entry IDs
typedef struct v_entries {
  unsigned long count;
  char **list;
} v_entries;

// An archive resource
typedef struct v_resource {
  unsigned char *data;
  unsigned long long len;
  unsigned int flags;
  unsigned char content_version;
  bool verified;
} v_resource;

// The version of the library
unsigned short version(void);

// Create new loader configuration
const v_archive_config *new_archive_config(const unsigned char (*magic)[V_MAGIC_LENGTH], const unsigned char (*pk_bytes)[V_PUBLIC_KEY_LENGTH], int *error_p);

// Free archive loader configuration
void free_archive_config(v_archive_config *config);

// Create a new archive from a file
v_archive *new_archive_from_file(const char *path, const v_archive_config *config, int *error_p);

// Create a new archive from a buffer
v_archive *new_archive_from_buffer(const v_archive_config *config, const unsigned char *data, unsigned long long len, int *error_p);

void free_archive(v_archive *archive);

// Get a list of archive entry IDs
const struct v_entries *archive_get_entries(const v_archive *archive, int *error_p);

void free_entries(const struct v_entries *entries);

// Fetch a resource, WITHOUT locking the internal Mutex
const struct v_resource *archive_fetch_resource(v_archive *archive, const char *id, int *error_p);

// Fetch a resource, LOCKS the internal Mutex
const struct v_resource *archive_fetch_resource_lock(const v_archive *archive, const char *id, int *error_p);

void free_resource(const struct v_resource *resource);
