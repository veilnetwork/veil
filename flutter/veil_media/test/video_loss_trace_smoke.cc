#include "veil_video_loss_trace.h"
#include <array>
#include <cassert>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>

int main(int argc, char** argv) {
  assert(argc == 2);
  const char* path = argv[1];
  { std::ofstream empty(path); assert(empty.good()); }
  setenv("VEIL_MEDIA_DIAG_PATH", path, 1);
  // Marker, padding, one CSRC and one extension word; only one media byte.
  std::array<uint8_t, 26> rtp{0xb1, 0xe0, 0xff, 0xff, 0,0,0,9, 0,0,0,7};
  rtp[18]=0; rtp[19]=1; rtp[24]=42; rtp[25]=1;
  std::array<uint8_t, 32> rr{0x81,201,0,7, 0,0,0,8,
    0,0,0,7, 5,0xff,0xff,0xff, 0,1,0,4, 0,0,0,6, 0,0,0,2, 0,0,0,3};
  { veil_media::VideoLossTrace disabled(false); disabled.Rtp(rtp,7,'s',1,0); disabled.Rtcp(rr,'r',2,0); }
  assert(std::ifstream(path, std::ios::binary|std::ios::ate).tellg()==0);
  {
    veil_media::VideoLossTrace trace(true,2,1);
    trace.Rtp(rtp,8,'s',1,0); // foreign SSRC is not video evidence
    auto broken=rtp; broken.back()=0; trace.Rtp(broken,7,'s',1,0);
    broken=rtp; broken[19]=100; trace.Rtp(broken,7,'s',1,0);
    trace.Rtp(rtp,7,'s',10,1); trace.Rtp(rtp,7,'r',20,0); trace.Rtp(rtp,7,'d',21,0);
    trace.Rtcp(rr,'s',11,0); trace.Rtcp(rr,'r',30,0);
    // Valid report followed by a truncated block must publish no prefix.
    std::array<uint8_t,36> compound{}; std::copy(rr.begin(),rr.end(),compound.begin());
    compound[32]=0x80; compound[33]=201; compound[35]=7;
    trace.Rtcp(compound,'r',31,0);
    auto truncated=rr; truncated[0]=0x82; trace.Rtcp(truncated,'r',32,0);
    trace.Flush(); trace.Rtcp(rr,'r',33,0); trace.Flush();
  }
  std::ifstream input(path); std::string text((std::istreambuf_iterator<char>(input)),{});
  assert(text.find("packets=2 packet_seen=3 reports=1 report_seen=2 malformed=2")!=std::string::npos);
  assert(text.find("seq=65535 timestamp=9 bytes=26 payload=1 marker=1 result=1")!=std::string::npos);
  assert(text.find("reporter=8 ssrc=7 fraction=5 lost=-1 highest=65540 jitter=6 lsr=2 dlsr=3")!=std::string::npos);
  assert(text.find("write_ok=1")!=std::string::npos);
  {
    veil_media::VideoLossTrace trace(true,1,1);
    std::array<std::thread,4> threads;
    for(auto& t:threads)t=std::thread([&]{for(int i=0;i<100;++i){trace.Rtp(rtp,7,'s',i,0);trace.Rtcp(rr,'r',i,0);}});
    for(auto& t:threads)t.join();
  }
  std::ifstream tail(path); text.assign(std::istreambuf_iterator<char>(tail),{});
  assert(text.find("packets=1 packet_seen=400 reports=1 report_seen=400 malformed=0")!=std::string::npos);
  std::remove(path);
}
