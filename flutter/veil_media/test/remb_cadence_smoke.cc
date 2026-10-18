#include "veil_remb_cadence.h"
#include <cassert>
#include <vector>

void Word(std::vector<uint8_t>& p, size_t at, uint32_t value) {
  for (int i = 0; i < 4; ++i) p[at+i] = value >> (24-i*8);
}
std::vector<uint8_t> Estimate(uint32_t rate = 32000) {
  // Empty SR, CNAME SDES, REMB for one receiver.
  std::vector<uint8_t> p(64);
  p[0]=0x80; p[1]=200; p[3]=6; Word(p,4,9);
  p[28]=0x81; p[29]=202; p[31]=2; Word(p,32,9); p[36]=1;
  p[40]=0x8f; p[41]=206; p[43]=5; Word(p,44,9);
  p[52]='R';p[53]='E';p[54]='M';p[55]='B';p[56]=1;
  p[57]=(rate>>16)&3;p[58]=rate>>8;p[59]=rate;Word(p,60,10);
  return p;
}
int main() {
  veil_media::RembCadence gate;
  const auto base=Estimate(), up=Estimate(48000), down=Estimate(16000);
  assert(gate.Allow(base,100,1));
  // Merely evaluating or failing a send cannot consume an opportunity.
  assert(gate.Allow(base,101,1));
  gate.Accepted(base,100,1);
  assert(!gate.Allow(base,101,1) && !gate.Allow(up,101,1));
  assert(gate.Allow(down,101,1) && gate.Allow(Estimate(0),101,1));
  assert(!gate.Allow(base,1'000'099,1));
  assert(gate.Allow(base,1'000'100,1));
  assert(gate.Allow(base,99,1) && gate.Allow(base,101,2));
  auto changed=base;Word(changed,60,11);assert(gate.Allow(changed,101,1));
  changed=base;Word(changed,4,11);assert(gate.Allow(changed,101,1));
  // Loss-bearing SR/RR, NACK, PLI/FIR, APP, XR and unknown feedback stay immediate.
  for (auto type : {201,204,205,206,207,210}) {
    changed=base; changed.insert(changed.end(),{0x81,uint8_t(type),0,1,0,0,0,0});
    assert(gate.Allow(changed,101,1));
  }
  changed=base;changed[0]=0x81;assert(gate.Allow(changed,101,1));
  changed=base;changed[36]=2;assert(gate.Allow(changed,101,1));
  changed=base;changed[37]=255;assert(gate.Allow(changed,101,1));
  for (size_t end=0;end<base.size();++end)
    assert(gate.Allow(std::span<const uint8_t>(base.data(),end),101,1));
  changed=base;changed[57]=255;assert(gate.Allow(changed,101,1));
  gate.Reset(); assert(gate.Allow(up,101,1));
  // Committing a decrease establishes the new conservative growth ceiling.
  gate.Accepted(down,200,1);
  assert(!gate.Allow(up,201,1));
}
