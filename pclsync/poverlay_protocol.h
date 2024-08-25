// defines the messaging protocol for pclsync

#ifndef POVERLAY_SOCK_PATH
#define POVERLAY_SOCK_PATH "/tmp/pcloud_unix_soc.sock"
#endif

typedef struct _message {
  uint32_t type;
  uint64_t length;
  char value[];
} message;

// represents a request message
typedef message request_message;

// represents a response message; this includes the API response
// message and any payload data returned by the callback function.
typedef struct {
  message *msg;     // API response message
  void *payload;    // data returned by the callback function
  size_t payloadsz; // size of payload
} response_message;
