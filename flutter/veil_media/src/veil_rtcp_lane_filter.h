#ifndef VEIL_MEDIA_RTCP_LANE_FILTER_H_
#define VEIL_MEDIA_RTCP_LANE_FILTER_H_

#include <algorithm>
#include <cstdint>
#include <span>
#include <vector>
#include "modules/rtp_rtcp/source/rtcp_packet/common_header.h"
#include "modules/rtp_rtcp/source/rtcp_packet/remb.h"

namespace veil_media {

struct RtcpLanePacket {
  bool valid = false;
  uint64_t foreign_remb_blocks = 0;
  std::vector<uint8_t> bytes;
};

// Endpoint-only demux after authentication. Upstream RTCPReceiver filters
// report blocks and TWCC by SSRC, but accepts REMB without checking its target
// list. Copying a video's REMB to the audio Call can change audio's allocation
// and Opus packet duration. Retain all other blocks, including mixed reports.
inline RtcpLanePacket FilterRtcpForSender(std::span<const uint8_t> packet,
                                         uint32_t local_ssrc) {
  RtcpLanePacket result;
  result.bytes.reserve(packet.size());
  for (size_t offset = 0; offset < packet.size();) {
    webrtc::rtcp::CommonHeader header;
    if (!header.Parse(packet.data() + offset, packet.size() - offset))
      return {};
    bool retain = true;
    if (header.type() == 206 && header.count() == 15 &&
        header.payload_size_bytes() >= 16) {
      webrtc::rtcp::Remb remb;
      if (remb.Parse(header) && !remb.ssrcs().empty()) {
        retain = std::find(remb.ssrcs().begin(), remb.ssrcs().end(), local_ssrc)
                 != remb.ssrcs().end();
        if (!retain) ++result.foreign_remb_blocks;
      }
    }
    if (retain) {
      const auto block = packet.subspan(offset, header.packet_size());
      result.bytes.insert(result.bytes.end(), block.begin(), block.end());
    }
    offset += header.packet_size();
  }
  // Empty target lists carry no positive stream assignment. Preserve their
  // existing compatibility behavior; do not invent a target from sender SSRC.
  result.valid = !packet.empty();
  return result;
}

}  // namespace veil_media
#endif
