#pragma once

#include "api/call/transport.h"

namespace veil_media {

// The producing WebRTC Call knows which RTCP state it owns. Preserve that
// information locally instead of guessing from compound report SSRCs. The
// owner and this adapter must outlive every stream using it.
template <typename Owner>
class VideoControlTransport final : public webrtc::Transport {
 public:
  explicit VideoControlTransport(Owner& owner) : owner_(owner) {}

  bool SendRtp(std::span<const uint8_t> packet,
               const webrtc::PacketOptions& options) override {
    return owner_.SendRtp(packet, options);
  }

  bool SendRtcp(std::span<const uint8_t> packet,
                const webrtc::PacketOptions& options) override {
    return owner_.SendVideoRtcp(packet, options);
  }

 private:
  Owner& owner_;
};

}  // namespace veil_media
