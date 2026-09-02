use crate::ArgVerbosity;
use std::{
    os::raw::{c_char, c_void},
    sync::Mutex,
};

pub(crate) static DUMP_CALLBACK: Mutex<Option<DumpCallback>> = Mutex::new(None);

/// # Safety
///
/// set dump log info callback.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tun2proxy_set_log_callback(
    callback: Option<unsafe extern "C" fn(ArgVerbosity, *const c_char, *mut c_void)>,
    ctx: *mut c_void,
) {
    *DUMP_CALLBACK.lock().unwrap() = Some(DumpCallback(callback, ctx));
    // AND THEN WAIT for the previous one to finish.
    //
    // The call below runs with the registry lock RELEASED — it has to, or a
    // callback that logs takes the lock its own caller holds (report14
    // V14-L5) — which leaves a window where the host can unregister and free
    // the `ctx` a thread is about to pass back to it. Returning from this
    // setter now means no thread is still inside the old callback, so the ctx
    // it was given is the host's to free (report20 V18-M10).
    IN_FLIGHT.wait_for_quiet();
}

/// Threads currently inside the dump callback. See [`crate::ffi_callback`].
static IN_FLIGHT: crate::ffi_callback::InFlight = crate::ffi_callback::InFlight::new();

#[derive(Clone)]
pub struct DumpCallback(Option<unsafe extern "C" fn(ArgVerbosity, *const c_char, *mut c_void)>, *mut c_void);

impl DumpCallback {
    unsafe fn call(self, dump_level: ArgVerbosity, info: *const c_char) {
        if let Some(cb) = self.0 {
            unsafe { cb(dump_level, info, self.1) };
        }
    }
}

unsafe impl Send for DumpCallback {}
unsafe impl Sync for DumpCallback {}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DumpLogger {}

impl log::Log for DumpLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Trace
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let current_crate_name = env!("CARGO_CRATE_NAME");
            if record.module_path().unwrap_or("").starts_with(current_crate_name) {
                self.do_dump_log(record);
            }
        }
    }

    fn flush(&self) {}
}

impl DumpLogger {
    fn do_dump_log(&self, record: &log::Record) {
        let timestamp: chrono::DateTime<chrono::Local> = chrono::Local::now();
        let msg = format!(
            "[{} {:<5} {}] - {}",
            timestamp.format("%Y-%m-%d %H:%M:%S"),
            record.level(),
            record.module_path().unwrap_or(""),
            record.args()
        );
        let c_msg = std::ffi::CString::new(msg).unwrap();
        let ptr = c_msg.as_ptr();
        // Copied out and the lock RELEASED before the call — a callback that
        // logs, or that installs another callback, would otherwise take the
        // mutex its own caller is holding (report14 V14-L5).
        let cb = DUMP_CALLBACK.lock().ok().and_then(|g| g.clone());
        if let Some(cb) = cb {
            // Counted for the whole call, so an unregister that starts now
            // waits for this to return before it lets the host free `ctx`.
            let _in_flight = IN_FLIGHT.enter();
            unsafe {
                cb.call(record.level().into(), ptr);
            }
        }
    }
}
