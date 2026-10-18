gates.sh        guest gates (K2, K3 auto, K4 campaign --no-suite on kjit-guest and kjit-guest-debug), own KJIT_BUILD_ROOT
                (.kjit/build of the a22-budget worktree: symlinked shared kernel Images + rootfs, kjit-module = mod-a22budget).
census_verify.patch
                patch against ../../0122-a21-words/tools/census.rs: also runs compile_request + the verifier on every fragment
                the census translates (stderr lines "VERIFY ok|REJECTED|compile-error"); output in ../census/verify/.
Census: ../../0122-a21-words/tools/run.sh ELFDIR TREE OUTDIR, then census.py (ELFs md5 equal to
../../../2026-10-14/1602-word-census/logs/elf-md5.txt). main = git archive 5f14f89, a22b = this tree.
