# Table of contents

- [Photon](#photon)
  - [PHTN-50-000192 The pam_faillock would record login failure regardless of pam_unix.so's return code, thus treating login success as failures.](#phtn-50-000192-the-pam-faillock-would-record-login-failure-regardless-of-pam_unix.so's-return-code-thus-treating-login-success-as-failures.)

# Known Issues

This document outlines known issues with the Photon 5.0 STIG Readiness Guide content, including workarounds if known.

## What should I do if...

### I have additional questions about an issue listed here?

Each known issue links off to an existing GitHub issue. If you have additional questions or feedback, please comment on the issue.

### My issue is not listed here?

Please check the [open](https://github.com/vmware/dod-compliance-and-automation/issues) and [closed](https://github.com/vmware/dod-compliance-and-automation/issues?q=is%3Aissue+is%3Aclosed) issues in the issue tracker for the details of your bug. If you can't find it, or if you're not sure, open a new issue.

## Photon

### [PHTN-50-000192] - The pam_faillock would record login failure regardless of pam_unix.so's return code, thus treating login success as failures.

Related issue: None

We believe that it was originally wrongly assumed the `pam_faillock.so authfail` would only be executed if previous rules reported failures. However, in reality, each rule does not depend on the return status of previous rules. Instead, each rule can branch to other rules or terminate the processing based on it's own return code. Essentially, think of the rules as C functions with prototype `int pam_func(args...)`, and the required/requisite/sufficient/optional as the `if` branches act on the return codes. Specifically:

```
required   = [success=ok new_authtok_reqd=ok ignore=ignore default=bad]
requisite  = [success=ok new_authtok_reqd=ok ignore=ignore default=die]
sufficient = [success=done new_authtok_reqd=done default=ignore]
optional   = [success=ok new_authtok_reqd=ok default=ignore]
```

E.g., for "required pam_unix.so", if pam_unix(...) gives success(0), then use this return code to override the previous return code, if any. If pam_unix(...) gives errors other than new_authtok_reqd(12) or ignore(25), then use the return code, if it's the first one, as the return code of the whole stack.

Therefore, the examples on the man page has the following (which only invoke the pam_faillock.so authfail when needed):

```
auth     [success=1 default=bad] pam_unix.so       # Jump to pam_faillock.so authsucc if returns success(0)
auth     [default=die]  pam_faillock.so authfail
auth     sufficient     pam_faillock.so authsucc
```
Or
```
auth     sufficient     pam_unix.so                # Exit the stack if returns success(0)
auth     [default=die]  pam_faillock.so authfail   # Else, let the pam_failllock.so abort the whole stack
auth     required       pam_deny.so
```
With the original config on the top, pam_faillock would record login failure regardless of pam_unix.so's return code, thus treating login success as failures. The system-auth would be changed to:
```
Begin /etc/pam.d/system-auth

auth    required      pam_faillock.so preauth
auth    sufficient    pam_unix.so                 # Exit the stack if returns success(0)
auth    required      pam_faillock.so authfail    # Else, record failure
auth    optional      pam_faildelay.so delay=4000000
auth    required      pam_deny.so                 # Need this as pam_faillock.so authfail will return ignore(25)
                                                  # And we want to fail the authentication explicitly

End /etc/pam.d/system-auth
```

**Workaround:**

- We will fix this issue in a future STIG update. For now as workaround in the system-auth file replace 
`auth    required    pam_unix.so` 
with 
`auth    sufficient    pam_unix.so`

