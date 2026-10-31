// C interface to the stash vault, implemented in Rust (crates/stash-ffi).
// See src/lib.rs for the rules: one thread per vault, free every returned
// string with stash_string_free (it wipes it), errors come back through
// `error` as strings to free the same way.

#ifndef STASH_H
#define STASH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct StashVault StashVault;

bool stash_check_vault(const char *path, char **error);
StashVault *stash_create(const char *path, const uint8_t *password, size_t len, char **error);
bool stash_add_payment(StashVault *vault, const char *name, const char *json, char **error);
bool stash_update_payment(StashVault *vault, const char *name, const char *json, char **error);
bool stash_remove(StashVault *vault, const char *name, char **error);
StashVault *stash_open_password(const char *path, const uint8_t *password, size_t len, char **error);
StashVault *stash_open_keys(const char *path, const uint8_t *keys /* 64 bytes */, char **error);
bool stash_copy_keys(const StashVault *vault, uint8_t *out /* 64 bytes */);
char *stash_list(const StashVault *vault, char **error);
char *stash_item(const StashVault *vault, const char *name, char **error);
char *stash_reveal(const StashVault *vault, const char *name, const char *field, char **error);
void stash_close(StashVault *vault);
void stash_string_free(char *s);

#endif
