#!/bin/sh
# Does the tutorial still compile?
#
# Crypto/Tutorial.hs is the one place in the package whose code the compiler
# never sees: every example in it is a Haddock block, so an API change
# silently leaves it wrong and the next reader copies something that does
# not build.  That has happened -- taking a checked key in Poly1305 made the
# tutorial's crypto_box stop type-checking, and it was noticed by reading
# the module rather than by anything here.
#
# So the blocks are pulled out and type-checked.  Each one becomes a module
# of its own, because each one is a thing a reader copies whole; a block
# that needs a definition from the block above it will fail here, which is
# the right answer.
#
# Checked against this tree rather than against whatever crypton is
# installed: cabal repl has the project's library as its home package, so a
# tutorial written for an API this working tree has not got cannot pass by
# finding the API in a released version on the machine.  -fno-code because
# nothing is run -- the question is only whether it compiles.
#
# -Wall as well, and a warning in a tutorial counts as a failure: an unused
# import is three words a reader will paste into their own file.  Only the
# extracted modules are held to it, not the library loaded beside them.
#
# The first module is wrong on purpose and has to be reported, or the run
# proves nothing: a repl that failed to start, a ghci whose message format
# changed, or an extractor that produced no modules would otherwise all look
# like a tutorial that compiles.
set -eu

cd "$(dirname "$0")/../.."
tutorial=Crypto/Tutorial.hs

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT INT TERM

modules=$(awk -v out="$work" -f tests/tutorial/extract.awk "$tutorial")
count=$(printf '%s\n' "$modules" | grep -c . || true)
if [ "$count" -eq 0 ]; then
    echo "FAIL no code blocks found in $tutorial"
    exit 1
fi
echo "$count code blocks in $tutorial"

# The deliberate one.  hashWith returns a Digest, and has since the module
# was written, so this is the shape of every break this harness is for: the
# tutorial says something the library no longer agrees with.
cat > "$work/Calibration.hs" <<'HS'
module Calibration where
import Crypto.Hash (SHA1 (..), hashWith)
thisIsNotADigest :: Int
thisIsNotADigest = hashWith SHA1 "the harness has to report this"
HS

{
    echo ':!echo @@ Calibration'
    echo ":load $work/Calibration.hs"
    for m in $modules; do
        echo ":!echo @@ $m"
        echo ":load $work/$m.hs"
    done
    echo ':quit'
} > "$work/script"

# Not cabal's -v0: that reaches ghci too and takes the "Ok, N modules
# loaded." line with it, which is what is read below.
cabal repl crypton --repl-options=-i"$work" --repl-options=-fno-code \
    --repl-options=-Wall --repl-options=-Wno-missing-home-modules \
    < "$work/script" > "$work/log" 2>&1 || true

awk -v expected="$count" '
    # ghci writes its prompt before the echo, so the marker is at the end
    # of the line rather than the start of it.
    /@@ [A-Za-z_]/ { mod = $NF; verdict[mod] = "no answer"; order[++n] = mod; next }
    mod == "" { next }
    /^Ok, [0-9]+ modules? loaded\.$/     { verdict[mod] = "ok";     next }
    /^Failed, [0-9]+ modules? loaded\.$/ { verdict[mod] = "failed"; next }
    # Only the extracted modules are held to -Wall; the library is loaded
    # beside them and is not what this is asking about.
    /Example_[A-Za-z0-9_]*\.hs:[0-9]+:[0-9]+: warning:/ { warned[mod] = 1 }
    # Everything ghci said about a module before it gave its verdict, minus
    # the progress lines, which are the bulk of it and say nothing.
    /^(ghci> )?\[ *[0-9]+ of [0-9]+\] Compiling/ { next }
    { if (verdict[mod] == "no answer" && $0 != "") detail[mod] = detail[mod] $0 "\n" }
    END {
        bad = 0
        for (i = 1; i <= n; i++) {
            m = order[i]
            want = (m == "Calibration") ? "failed" : "ok"
            got = verdict[m]
            if (got == want && want == "ok" && warned[m]) got = "warned"
            if (got == want) {
                printf "ok   %s%s\n", m, (m == "Calibration" ? "   (reported, as it must be)" : "")
            } else {
                bad++
                printf "FAIL %s: expected %s, got %s\n", m, want, got
                printf "%s", detail[m]
            }
        }
        # Nothing answered, or not everything did: the run itself did not
        # happen the way this script assumes, so the log is worth seeing.
        if (n != expected + 1) {
            printf "FAIL %d modules answered, %d expected\n", n - 1, expected
            exit 2
        }
        exit (bad > 0)
    }
' "$work/log" || {
    status=$?
    if [ "$status" -eq 2 ]; then
        echo
        echo "--- the last of the log ---"
        tail -60 "$work/log"
    fi
    exit 1
}

echo "every example in $tutorial compiles"
