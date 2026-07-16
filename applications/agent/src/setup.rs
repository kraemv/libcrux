use libc::{
    mlockall, prctl, MCL_FUTURE, PR_SET_DUMPABLE, PR_SET_PDEATHSIG,
    PR_SET_SPECULATION_CTRL, PR_SPEC_FORCE_DISABLE, PR_SPEC_STORE_BYPASS, SIGHUP,
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

        assert!(mlockall(MCL_FUTURE) == 0);
    }

    // TODO: Maybe add cap here?
}
