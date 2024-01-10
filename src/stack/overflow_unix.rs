use crate::rt::guard;

use crate::stack::sys::page_size;
use libc::{sigaction, sighandler_t, SA_ONSTACK, SA_SIGINFO, SIGBUS, SIGSEGV};
use std::mem;
use std::ptr::null_mut;
use std::sync::{Once, OnceLock};

static SIG_ACTION: OnceLock<sigaction> = OnceLock::new();

// Signal handler for the SIGSEGV and SIGBUS handlers. We've got guard pages
// (unmapped pages) at the end of every coroutine's stack, so if a coroutine ends
// up running into the guard page it'll trigger this handler. We want to
// detect these cases and print out a helpful error saying that the stack
// has overflowed. All other signals, however, should go back to what they
// were originally supposed to do.
//
// If this is not a stack overflow, the handler un-registers itself and
// then returns (to allow the original signal to be delivered again).
// Returning from this kind of signal handler is technically not defined
// to work when reading the POSIX spec strictly, but in practice it turns
// out many large systems and all implementations allow returning from a
// signal handler to work. For a more detailed explanation see the
// comments on https://github.com/rust-lang/rust/issues/26458.
unsafe extern "C" fn signal_handler(
    signum: libc::c_int,
    info: *mut libc::siginfo_t,
    ctx: *mut libc::ucontext_t,
) {
    let _ctx = &mut *ctx;
    let addr = (*info).si_addr() as usize;
    let stack_guard = guard::current();

    let ps = page_size();

    if stack_guard.start - ps > addr {
        // it is unlikely to overflow so we drop a hint to the compiler with #[cold] attribute
        #[cold]
        #[inline]
        fn overflow_fallback() {
            eprintln!(
                "\ncoroutine in thread '{}' has overflowed its stack\n",
                std::thread::current().name().unwrap_or("<unknown>")
            );

            std::process::abort();
        }

        overflow_fallback();
    }

    if !stack_guard.contains(&addr) {
        // SIG_ACTION is available after we registered our handler
        sigaction(
            signum,
            SIG_ACTION.get().unwrap_or_else(|| {
                eprintln!("unable to get original sigaction");

                std::process::abort();
            }),
            null_mut(),
        );

        // we are unable to handle this
        return;
    }

    let usage = stack_guard.end - addr;
    let mul = (usage / ps).max(1);
    let extended = ps * mul * 2;

    if libc::mprotect(
        (stack_guard.end - extended) as _,
        extended,
        libc::PROT_READ | libc::PROT_WRITE,
    ) != 0
    {
        eprintln!(
            "\ncoroutine in thread '{}' is unable to extend its stack\n",
            std::thread::current().name().unwrap_or("<unknown>")
        );

        std::process::abort();
    }

    let mut sigset: libc::sigset_t = mem::zeroed();
    libc::sigemptyset(&mut sigset);
    libc::sigaddset(&mut sigset, signum);
    libc::sigprocmask(libc::SIG_UNBLOCK, &sigset, null_mut());

    // we go back and continue our coroutine.
    // about the behavior of return, please see the comment of this function.
    return;
}

#[cold]
unsafe fn init() {
    let mut action: sigaction = mem::zeroed();

    action.sa_flags = SA_SIGINFO | SA_ONSTACK;
    action.sa_sigaction = signal_handler as sighandler_t;

    let mut origin = mem::zeroed();

    for signal in [SIGSEGV, SIGBUS] {
        sigaction(signal, &action, &mut origin);
    }

    let _ = SIG_ACTION.set(origin);
}

pub fn init_once() {
    static INIT_ONCE: Once = Once::new();

    INIT_ONCE.call_once(|| unsafe {
        init();
    })
}
