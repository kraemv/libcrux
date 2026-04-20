use libc::{
    mlockall, prctl, sigfillset, sigprocmask, MCL_FUTURE, PR_SET_DUMPABLE, PR_SET_PDEATHSIG,
    PR_SET_SPECULATION_CTRL, PR_SPEC_FORCE_DISABLE, PR_SPEC_STORE_BYPASS, SIGHUP, SIG_BLOCK,
};

pub(crate) fn do_setup() {
    unsafe {
        assert!(
            prctl(
                PR_SET_SPECULATION_CTRL,
                PR_SPEC_STORE_BYPASS,
                PR_SPEC_FORCE_DISABLE,
                0,
                0,
            ) >= 0,
        );
        assert!(prctl(PR_SET_DUMPABLE, 0) == 0);
        assert!(prctl(PR_SET_PDEATHSIG, SIGHUP) == 0);

        let mut mask: libc::sigset_t = std::mem::zeroed();
        sigfillset(&mut mask);
        assert_eq!(
            sigprocmask(
                SIG_BLOCK,
                &mask as *const libc::sigset_t,
                std::ptr::null_mut(),
            ),
            0
        );

        assert!(mlockall(MCL_FUTURE) == 0);
    }

    // TODO: Maybe add cap here?
}
