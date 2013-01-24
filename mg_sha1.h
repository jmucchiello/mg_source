typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

REPLACE_STATIC void SHA1Init(SHA1_CTX* context);
REPLACE_STATIC void SHA1Update(SHA1_CTX* context, const unsigned char* data,
                       uint32_t len);
REPLACE_STATIC void SHA1Final(unsigned char digest[20], SHA1_CTX* context);
                       


