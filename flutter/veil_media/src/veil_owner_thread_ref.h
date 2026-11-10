// Keep the last intrusive reference until the owning thread can release it.
#ifndef VEIL_OWNER_THREAD_REF_H_
#define VEIL_OWNER_THREAD_REF_H_

#include <cassert>
#include <functional>
#include <utility>

namespace veil_media {

// Declare before every other member that can reference the object. Reverse
// member destruction then drops those references first. Dispatch must execute
// synchronously and must not abandon the closure. Capture only the raw owning
// reference: a ref-counted closure could itself be destroyed on the caller.
template <typename Ref>
class OwnerThreadRef {
 public:
  using Dispatch = void (*)(std::function<void()>);
  explicit OwnerThreadRef(Dispatch dispatch) : dispatch_(dispatch) {}
  OwnerThreadRef(const OwnerThreadRef&) = delete;
  OwnerThreadRef& operator=(const OwnerThreadRef&) = delete;

  void Retain(const Ref& ref) {
    assert(!retained_ && "owner-thread lifetime reference is installed once");
    retained_ = ref;
  }

  ~OwnerThreadRef() {
    auto* raw = retained_.release();
    if (raw) dispatch_([raw] { raw->Release(); });
  }

 private:
  Dispatch dispatch_;
  Ref retained_;
};

}  // namespace veil_media
#endif  // VEIL_OWNER_THREAD_REF_H_
