#ifndef VEIL_PACKET_TUNNEL_FFI_H
#define VEIL_PACKET_TUNNEL_FFI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*VeilPacketWriteFn)(void *context,
                                  const uint8_t *data,
                                  uintptr_t length);

int32_t veil_packet_tunnel_start_packets(const char *proxy_url,
                                         const char *dns_ip,
                                         uint16_t mtu,
                                         bool ipv6_enabled,
                                         bool route_dns,
                                         VeilPacketWriteFn write_callback,
                                         void *write_context);
int32_t veil_packet_tunnel_send_packet(const uint8_t *data, uintptr_t length);
int32_t veil_packet_tunnel_status(void);
int32_t veil_packet_tunnel_stop(void);
char *veil_packet_tunnel_last_error(void);
void veil_free_string(char *value);

#ifdef __cplusplus
}
#endif

#endif
