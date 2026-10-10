# Pull every code block out of a Haddock module and write each one as a
# compilable Haskell module.
#
# A block is a maximal run of lines beginning "-- >", which is what Haddock
# renders as a code sample.  The run is ended by any line that is not one,
# so two samples separated by a line of prose are two modules and cannot
# refer to each other -- which is the point: each sample has to stand on its
# own, because that is how a reader will copy it.
#
# The name comes from the "-- $section" marker the block sits under, so a
# compiler message names the section of the tutorial that is wrong rather
# than a number.  The module header goes after any LANGUAGE pragmas, since
# those have to come first.
#
# Writes one file per block into the directory given as -v out=, and prints
# each module name on stdout.

/^-- \$[A-Za-z_][A-Za-z0-9_]*$/ {
    section = substr($0, 5)
    nth = 0
    next
}

/^-- >/ {
    if (!inblock) {
        inblock = 1
        nlines = 0
        nth++
        mod = "Example_" section "_" nth
        file = out "/" mod ".hs"
    }
    # "-- > foo" carries a space that is not part of the code; "-- >" alone
    # is a blank line inside the block.
    line = (length($0) > 5) ? substr($0, 6) : ""
    lines[++nlines] = line
    next
}

{ if (inblock) flush() }

END { if (inblock) flush() }

function flush(   i, k) {
    # Pragmas, then the header, then the rest.
    k = 1
    while (k <= nlines && (lines[k] ~ /^\{-#/ || lines[k] == "")) k++
    for (i = 1; i < k; i++) print lines[i] > file
    print "module " mod " where" > file
    for (i = k; i <= nlines; i++) print lines[i] > file
    close(file)
    print mod
    inblock = 0
}
