#include "veil_rtcp_lane_filter.h"
#include "modules/rtp_rtcp/source/rtcp_packet/receiver_report.h"
#include <cstdio>
#include <cstdlib>

static void require(bool ok) {
  if (!ok) {
    std::fputs("RTCP lane regression failed\n", stderr);
    std::abort();
  }
}

int main() {
  constexpr uint32_t audio = 0x11111111, video = 0x22222222;
  webrtc::rtcp::Remb remb;
  remb.SetSenderSsrc(0x33333333);
  remb.SetBitrateBps(80000);
  require(remb.SetSsrcs({video}));
  auto wire = remb.Build();
  const std::vector<uint8_t> video_wire(wire.data(), wire.data() + wire.size());
  auto a = veil_media::FilterRtcpForSender(video_wire, audio);
  auto v = veil_media::FilterRtcpForSender(video_wire, video);
  require(a.valid && a.bytes.empty() && a.foreign_remb_blocks == 1);
  require(v.valid && v.bytes == video_wire && v.foreign_remb_blocks == 0);

  // A compound RR still carries both streams' loss/RTT observations. Only the
  // foreign bitrate allocation is removed, never ordinary feedback or SDES.
  webrtc::rtcp::ReceiverReport rr;
  rr.SetSenderSsrc(0x33333333);
  webrtc::rtcp::ReportBlock block;
  block.SetMediaSsrc(audio);
  rr.AddReportBlock(block);
  block.SetMediaSsrc(video);
  rr.AddReportBlock(block);
  auto report = rr.Build();
  const std::vector<uint8_t> report_wire(report.data(), report.data() + report.size());
  auto compound = report_wire;
  compound.insert(compound.end(), video_wire.begin(), video_wire.end());
  a = veil_media::FilterRtcpForSender(compound, audio);
  v = veil_media::FilterRtcpForSender(compound, video);
  require(a.valid && a.bytes == report_wire && a.foreign_remb_blocks == 1);
  require(v.valid && v.bytes == compound && v.foreign_remb_blocks == 0);

  require(remb.SetSsrcs({audio, video}));
  wire = remb.Build();
  auto both = std::span<const uint8_t>(wire.data(), wire.size());
  require(veil_media::FilterRtcpForSender(both, audio).bytes.size() == wire.size());
  require(veil_media::FilterRtcpForSender(both, video).bytes.size() == wire.size());

  require(remb.SetSsrcs({}));
  wire = remb.Build();
  auto unknown = std::span<const uint8_t>(wire.data(), wire.size());
  require(veil_media::FilterRtcpForSender(unknown, audio).bytes.size() == wire.size());

  auto other_afb = video_wire;
  other_afb[12] = 'X';  // Another application-layer feedback message.
  require(veil_media::FilterRtcpForSender(other_afb, audio).bytes == other_afb);
  compound.pop_back();  // A truncated final block cannot partially apply.
  require(!veil_media::FilterRtcpForSender(compound, audio).valid);

  // CommonHeader strips valid trailing RTCP padding before REMB parsing.
  auto padded = video_wire;
  padded[0] |= 0x20;
  padded.insert(padded.end(), {0, 0, 0, 4});
  padded[3] += 1;
  require(veil_media::FilterRtcpForSender(padded, audio).bytes.empty());
  require(veil_media::FilterRtcpForSender(padded, video).bytes == padded);
  std::puts("RTCP REMB targets isolated; compound reports retained");
}
