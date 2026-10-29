# Native driver completion and containment

`OwnedDriver.run(..., require_natural_exit=True)` is an internal operator option.
It does not change the MCP tool surface or authorize a GUI target. The default
auxiliary/retained-start containment behavior is preserved.

Previously `run` waited for its root process, then unconditionally called
`TerminateJobObject`. Its cleanup receipt could report an empty Job even when
a descendant had required termination. That receipt proves containment, not
natural completion of the tree.

The opt-in path observes the root and live members of the exact Job before
resume and while waiting, retaining process handles. Each observation records
PID, creation FILETIME, executable image, parent PID, structural role, signal
state and actual exit code. Parent birth is joined only to a compatible observed
process; an unresolved parent birth remains null. This is not an assertion that
every short-lived intermediate process was sampled. Job accounting independently
establishes that no members remain.

Birth/image observation uses `GetProcessTimes` and `QueryFullProcessImageNameW`.
Parent information uses dynamically resolved `NtQueryInformationProcess` on the
held handle; this Windows API can change. An unavailable/failed query refuses
the proof rather than substituting process names or an unrelated numeric PID.
See [Microsoft's contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess).

Success requires actual root exit, zero active Job processes and signaled
observed members before closing handles. No terminate call occurs on that path.
The witness is bound to the Job creation observation, owner PID/birth and root.
Each registered execution result or outward execution exception carries its
detached `natural_exit` witness and `cleanup` receipt. Argument/admission refusals
before call registration carry no new execution witness; a poisoned owner may
rethrow its earlier cleanup failure. Neither is evidence of a new execution.
Acceptance must use the call-specific execution outcome;
the shared `last_natural_exit` / `last_cleanup` attributes are diagnostics only.
The cleanup receipt separately records whether termination was requested. Nonzero root exit codes remain
nonzero. Consumers requiring exit0 must check the code as well as Job0.

The existing operation deadline also bounds waiting for descendants. Cancellation,
identity failure or timeout still invokes only the existing owner-scoped failure
cleanup. Its post-containment Job0 cannot satisfy `natural_exit_verified`.
The retained-start option is incompatible with this completion mode.

Native regressions exercise delayed child exit, surviving descendants, cancellation,
identity-query failure and preservation of nonzero exit. Existing assignment,
timeout, quiescence and same-image foreign-neighbour tests remain required.
No Office, Makepad, GPU, WSLC or Core acceptance follows from these native tests.
