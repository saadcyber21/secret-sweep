# Fixtures

`clean/` is committed: ordinary code that must produce **zero** findings. CI
fails if it ever produces one.

There is no committed `dirty/` directory, and that is deliberate.

A secret scanner needs realistic-format credentials to test against, but
GitHub push protection rejects any push containing them — including the
placeholder credentials published in AWS's and Stripe's own documentation, which
are matched by format rather than by value. The
options are to bypass the protection, commit mangled values that no longer test
anything, or generate them at test time. This repo does the third.

`scripts/make_dirty_fixture.py` writes synthetic credentials into a temporary
directory using a fixed seed, so the run is reproducible while nothing that
looks like a real secret is ever committed. Both the test suite and CI call it.
