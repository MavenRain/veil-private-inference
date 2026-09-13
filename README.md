# veil

veil is kanon plus three host shapes for private computation: `SZk`
(zero-knowledge proof), `SFhc` (fully homomorphic ciphertext) and `SMpc`
(multi-party computation).  All three shapes check, erase and run with
the plaintext reactor twins in [REACTOR.md](REACTOR.md).  The trusted
kernel bound is 5250 lines.

The [private inference receipt release](inference/README.md) includes an encrypted
inference protocol, NVAT and Trustee adapters, real PLONK and BFV backends,
NVFlare HE/DP rounds, and a confidential-container deployment package.
The [plaintext milestone](examples/private-inference/README.md) checks mocked
attestation without a GPU. Hardware acceptance is a separate deployment step.

The plaintext proof runtime checks that verification uses the instance
stored by `zkProve`, as well as checking the supplied relation. The
[instance-binding validation](dev/ZK-INSTANCE.md) covers both runtime twins.
The host runtime also preserves arbitrary-precision natural values and
arithmetic results for all three shapes, as checked by the
[host natural validation](dev/HOST-NAT.md).
Concurrent reactor runs keep separate proof, ciphertext and share slots,
as checked by the [blob store isolation regressions](dev/BLOB-ISOLATION.md).
The reactor rejects missing or surplus request arguments before host effects,
as checked by the [request arity regressions](dev/REQUEST-ARITY.md).
It also validates the 0-or-1 list predicates while decoding each request,
as checked by the [list ABI regressions](dev/LIST-ABI.md).
Request decoding also has a shared limit of 1048576 list nodes, so cyclic
or endlessly growing request lists cannot keep the host traversing them.
The [request traversal regressions](dev/REQUEST-BOUNDS.md) cover the limit.
Long-running reactors can release host blob slots with operation 18. Released
handles stay invalid for the rest of the run, as checked by the
[blob release regressions](dev/BLOB-RELEASE.md).
The [process signal tests](dev/PROCESS-SIGNALS.md) synchronize with child
readiness before checking deadline escalation and process cleanup.
Temporary-directory requests keep empty and dot prefixes inside their root
and reject path separators, as checked by the
[directory regressions](dev/TEMP-DIRECTORY.md).
Reactors can unlink files and remove empty directories with operations 19 and 20,
completing temporary-file cleanup through the host API. The
[cleanup regressions](dev/FILE-CLEANUP.md) cover successful removal, rejected
requests and preservation of symlink targets.
Operation 21 moves existing files and directories, including replacing a destination
file. The [rename regressions](dev/FILE-RENAME.md) cover replacement and error handling.
Operation 22 lists direct directory entries as sorted, NUL-terminated raw names.
The [directory listing regressions](dev/DIRECTORY-LISTING.md) cover byte preservation,
the 65536-byte answer limit and directory-handle cleanup.
Operation 23 inspects filesystem entry kinds, including dangling symlinks.
The [entry kind regressions](dev/ENTRY-KIND.md) cover files, directories, links,
special files and path errors.
Operation 24 reads a symlink's stored target as raw bytes, including dangling
and cyclic links. The [symlink target regressions](dev/SYMLINK-TARGET.md)
cover literal targets, response bounds and request validation.
Operation 25 creates a symlink from a literal target and a new destination path.
The [symlink creation regressions](dev/SYMLINK-CREATE.md) cover target preservation,
destination conflicts, path errors and composition with file reads and cleanup.
Operation 26 creates hard links to existing filesystem entries. The
[hard-link regressions](dev/HARD-LINK.md) cover shared file contents, conflicts,
path errors and interaction with atomic replacement and unlink.

Function parameters can share a type and quantity:

```kanon
def subtract (x y : Nat) : Nat := natSub x y
```

Grouped binders also work in `fun`, arrow and pair types, family and
constructor declarations, typed match fields, and numeric case legs.
They expand to
consecutive binders in source order, as specified in [SPEC.md](SPEC.md#9-the-surface-grammar).

Kanon's type grammar uses left and right Kan extensions along shapes.
The [foundation audit](dev/FOUNDATION-AUDIT.md) records the remaining
obligation to derive the implemented inductive rules from their universal
properties.  The [indexed construction](dev/INDEXED-CONSTRUCTION.md)
supplies external Lean models for nullary/unary indexed signatures,
including vectors.  The [finite branching construction](dev/FINITARY-CONSTRUCTION.md)
extends initiality to arbitrary finite constructor arities.  The
[natural-family bridge](dev/MU-NAT-BRIDGE.md) connects one extracted
checked `SMu` declaration and its closed constructor fragment to the
constructed algebra. The [binary-tree bridge](dev/MU-TREE-BRIDGE.md) connects
a checked family with two recursive children and its mirror operation to
the finite branching construction. The [indexed-vector bridge](dev/MU-VECTOR-BRIDGE.md)
connects checked length indices and payload-preserving copy to the constructed
indexed algebra. The [finite-family bridge](dev/MU-FINITARY-BRIDGE.md)
derives a signature from any validated unindexed family in the direct-recursion
fragment, retaining arbitrary finite constructor arities. Its
[raw-term decoder](dev/MU-FINITARY-DECODE.md) reconstructs closed constructor values
with exact syntax certificates and roundtrip laws. The
[open constructor fragment](dev/MU-FINITARY-OPEN.md) adds scoped variables,
certified decoding and substitution laws for raw encoding and interpretation.
The [dependent elimination bridge](dev/MU-FINITARY-ELIM.md) derives dependent
constructor computation and uniqueness for the constructed finite-family
carrier, with agreement on closed and open constructor terms and both
reification inverse laws.
Its [substitution laws](dev/MU-FINITARY-ELIM-SUBST.md) preserve arbitrary
dependent variable witnesses under substitution and renaming of homogeneous
constructor terms, with explicit transport between the resulting fibres.
The [composition coherence laws](dev/MU-FINITARY-ELIM-COHERENCE.md) compare
successive semantic transports with the composed route, preserving the
supplied dependent witnesses through the change of environment.
The [dependent fusion laws](dev/MU-FINITARY-ELIM-FUSION.md) preserve
constructor-respecting transformations of witness types through elimination,
open induction, substitution and renaming. Constant fibres recover ordinary folds.
The [base-change laws](dev/MU-FINITARY-ELIM-BASE-CHANGE.md) extend this to
constructor-preserving maps between base algebras, retaining dependent witnesses
through pullback, composition, substitution and renaming.
General typed interpretation, compiler preservation and full Lean parity remain open.

Status: M1 Stage L implementation complete. The current compiler passed
all 21 gate legs, including REACTOR, RUNTIME and the binding performance
checks, on 2026-09-07. The [validation record](dev/M1-BUILD-LOG.md#current-compiler-validation-2026-09-07)
retains the source revision, complete output and measurements.
M1 exit is not ratified. The checker, elaborator,
erasure, WasmGC emitter and execution driver support strictly positive
indexed and mutual `mu` families, dependent matching, structural
recursion, arbitrary precision `Nat` arithmetic and exact-use `1` binders.
`auto`, `nu`, level variables and the deferred equality shape remain later
work.  The [build log](dev/M1-BUILD-LOG.md) records validation results and
open gates.
The [reactor build log](dev/REACTOR-BUILD-LOG.md) records the validation of
the reactor host runtime, its CLI and the realpath example.

## Checking a file

`kanon check FILE` parses the file, elaborates every declaration to the
kernel grammar and checks it against the declarations before it.  It
prints nothing and exits 0 when the whole file checks, and prints one
line on stderr and exits 1 when it does not, so a caller reads stdout as
the answer alone.  `kanon check --print FILE` adds the checked form of
every entry to stdout, one `def NAME : TYPE := BODY` or `axiom NAME :
TYPE` line per declaration, in kernel terms and in declaration order;
the golden files under test/golden hold exactly that text.  `kanon
axioms FILE` prints what the file postulates, one name per line in
declaration order, and prints nothing for a file that postulates
nothing, so the trust base of a checked file is one command away.  A
missing file and an unknown command exit 64, which a caller tells from
the exit 1 of a file that does not check.

A `(1 x : T)` binder requires exactly one runtime use on every reachable
path.  Sequential uses add, argument quantities scale uses, and case
branches are alternatives.  Types, annotations and erased arguments
contribute no runtime uses.  The checker also tracks closure captures,
constructor fields and let aliases.

## Erasing a file

`kanon check --erased FILE` checks the file first and then prints the
erased program to stdout, in declaration order.  Erasure drops every
type, every proposition, every proof and every binder the checker
stamped `0`, so the printed program holds the runtime content alone.  A
declaration with no runtime content prints as `erased NAME`.  A
postulate with a runtime type prints as `axiom NAME : REPR`, which the
host must supply.  A definition prints as one `rec [TID; ..]` line, the
types it names, and then one `fun` line for each function it lifts and
one for its own function.  The golden files test/golden/NAME.erased
hold exactly that text, one beside every test/golden/NAME.checked, and
the ERASE group of the suite compares the two byte for byte.

## Emitting a module

`kanon emit FILE -o OUT.wasm --export NAME` checks the file, erases it
and writes one WasmGC module to OUT.wasm.  The argument order is fixed.
The named definition must be a `Nat` of arity zero:  the module exports
one function with no parameter and an i32 answer, which calls that
definition and reads the answer out of its i31.  The command prints
nothing and exits 0 on success.  A file that does not check exits 1, as
`kanon check` does.  A form the emitter refuses prints one
`kanon: emit: MESSAGE` line on stderr and exits 2;  the refusals are a
postulate with no body, an export that is not a `Nat` of arity zero, and
unsupported forms such as strings and the delayed forms that arrive at
M2.  A usage error and a directory that does not exist exit 64.

`node dev/run-node.mjs OUT.wasm NAME` runs the module with no import and
prints the answer in decimal.  It exits 0 with the answer, 1 with a
`trap: MESSAGE` line when the module traps, 2 with an `invalid: MESSAGE`
line when the engine refuses the module, and 64 on a usage error.  A
natural uses an i31 through 1073741823 and a big-natural struct with
base-32768 limbs above it.  All five primitives compute exactly, promoting
before overflow and normalizing small results back to i31; `natSub`
truncates at zero.  Large decimal literals are accepted.  The export ABI
still requires an i31 answer, so exporting a larger final value traps.
Large intermediate values may produce a small exported observation.

```
_build/default/bin/kanon.exe emit test/fixtures/d01-lit-prims.kan \
  -o /tmp/d01.wasm --export main
node dev/run-node.mjs /tmp/d01.wasm main        # prints 17
_build/default/test/wasm.exe test               # the emission suite
zsh dev/encoder-subset.sh                       # the opcodes of SPEC.md
```

The emission suite reads every fixture that checks and defines `main`.
For each one it emits the module, assembles it with wasm-opt, compares
the text form with test/golden/NAME.wat byte for byte, takes the value
of `main` from the kernel alone and compares the answer of the node
runner with it.  It prints one `EMIT NAME OK` line per fixture, then
`WASM-OK P/T`, then `SUITE-WASM OK` or `SUITE-WASM FAIL`.  The modules
and their text forms land in `_build/wasm-suite`, or in the directory of
the second argument.

## Running a module

`kanon run FILE --export NAME [--host node|wasmtime|kernel|both]` checks
the file, erases it, emits one module that exports NAME and runs that
module.  The argument order is fixed, and any other shape is a usage
error.  The module goes to a temporary file, which leaves with its two
capture files when the run ends, so a run writes nothing into the tree.

```sh
kanon run test/fixtures/d06-closure-capture.kan --export main
kanon run test/fixtures/d06-closure-capture.kan --export main --host kernel
```

There are four host words.  `node` runs the module through
`dev/run-node.mjs`, and `wasmtime` runs it through
`dev/run-wasmtime.sh`.  Each runner prints the answer in decimal on
stdout and exits 0, prints `trap: TEXT` on stderr and exits 1, or prints
`invalid: TEXT` on stderr and exits 2.  `kernel` runs no module.  It
reduces the exported global with the evaluator, the oracle that the
emission suite trusts.  `both` runs node and then wasmtime and compares
the two answers, and `both` is the default when `--host` is absent.

The driver finds the two runners beside the executable, at the root four
directories above `_build/default/bin/kanon.exe`.  A runner that is not
at that root is a usage error that names the file it wants.

The answer alone goes to stdout, so a caller reads one decimal number.
Every diagnosis goes to stderr, as one line:  `kanon: run: HOST trap:
TEXT`, `kanon: run: HOST invalid: TEXT`, `kanon: run: trap on both
hosts`, or `kanon: run: hosts disagree: node OUTCOME wasmtime OUTCOME`,
where an outcome is the value or the word `trap`.

The exit codes are these.  0 is an answer, and the hosts that ran agree
on it.  1 is a file that does not check.  2 is an emission the wasm back
end refuses, or a host that refuses the module.  3 is two hosts that
disagree.  4 is a trap, on one host, on both hosts, or in the kernel,
where an exported value outside the i31 range raises a trap.
64 is a usage error, a missing file or a missing runner.

## Reusable modules

`kanon build FILE... -o OUT.wasm --export NAME` compiles ordered source
files into one module with ordinary function and value exports. Repeat
`--export NAME` to expose more definitions. Later files can use earlier
declarations. The Node reactor host drives an exported state machine and
performs its requested OS operations.

`runtime/reactor.kan` supplies reusable byte and argument lists, and
`examples/reactor-realpath.kan` resolves one path and prints the result.
Run a compiled reactor with `node runtime/run.mjs MODULE.wasm [ARG ...]`.
[REACTOR.md](REACTOR.md) gives the complete build command, export ABI,
operation table and CLI behavior.

The reactor twin of the zero-knowledge, homomorphic and multi party
operations has no security: it keeps each blob as a plain slot and exists
only to test the export ABI and the three postulates (D-15).

## The spines

`examples/m1-spine.kan` extends the M0 coverage with direct, mutual and
indexed recursion, dependent matching, restricted large elimination from
`Prop`, exact-use binders, large natural intermediates and small unary
agreement witnesses.  It has no postulates and its expected `main` is
`599`.  The mandatory M1 suite checks that answer on the kernel and both
Wasm hosts.

```sh
kanon axioms examples/m1-spine.kan
kanon run examples/m1-spine.kan --export main --host kernel
kanon run examples/m1-spine.kan --export main --host both
```

`examples/m0-spine.kan` is the M0 spine.  It postulates nothing, so
`kanon axioms examples/m0-spine.kan` prints nothing and exits 0.  Its
`main` is a `Nat` of arity zero, and the kernel, node and wasmtime all
answer `521`.

```sh
kanon run examples/m0-spine.kan --export main --host kernel
kanon run examples/m0-spine.kan --export main --host both
```

The file holds every row of the emission table of SPEC.md section 8.1:
the five prims, where `natSub` stops at zero and `natEq` and `natLt`
answer the two leg sum that a case reads back into a `Nat`;  a chain of
tail calls through a helper of arity two;  a pair built and projected on
both sides;  a three leg tuple built and projected;  a sum with two
payload free legs and two payload legs, cased on every leg, beside a
case that writes `as x return T`;  a closure with a parameter capture
and a closure with a let bound capture, each stored in a pair and
applied later;  a partial application under the arity and an application
over it;  a call through a function parameter, which reaches the generic
`apply<k>`;  the erased polymorphic identity used at `Nat`;  a nested
let with a case inside it;  the annotation form;  the literals;  and a
function over the empty sum, which carries the `unreachable` row without
a trap, because `main` never calls it.

It retains the surface forms accepted at M0, including a `(1 x : Nat)`
identity adapted to the exact-use rule.  Recursive declarations appear
in the M1 spine.  Comments name the rows and productions exercised, and
the line `-- main is 521` is the promise that the M0-E2E leg reads.

## The closure ABI

A function with a known name and a known arity is called through its own
typed signature, where each parameter and the answer keeps the runtime
type of its erased repr.  Every other head is a closure.  A closure is
one struct of three immutable fields:  the arity as an i32, the code as
a function reference, and the environment as an eq reference, which
holds a struct of the captures or a tagged zero when there is no
capture.  The code of a closure has the generic signature `fn<n>`, where
the environment, every argument and the answer are eq references, so one
wrapper joins the two conventions:  it reads the captures out of the
environment, casts each capture and argument to its typed form, and tail calls the
typed code.  A call whose arity the caller does not know goes through
the helper `apply<k>`, which reads the arity out of the closure:  an
equal arity is a tail call of the code, a smaller arity calls the code
and applies the arguments that are left to the answer, and a larger
arity builds a partial application that holds the closure and the
arguments so far.

Pairs, tuples and closure environments store their runtime fields as eq
references, and sum payloads use eq references too.  Field reads cast to
the checked type.  This keeps aggregate layouts compatible when an erased
type parameter is instantiated.  Cases retain their checked sum type,
so a sum returned through a generic call still has its branch information.

## Layout

```
dune-project        (lang dune 3.24) (name kanon)
PIN                 the vendored tot sha
SPEC.md             the closed grammar, the R0 counts, the sugar table
vendor/tot/         git submodule, checked out at PIN
lib/                library kanon_kernel
surface/            library kanon_surface
wasm/               library kanon_wasm: gc_encode.ml, link.ml, emit.ml
bin/kanon.ml        driver: check | emit | build | run | axioms | spec-count
bin/host.ml         the three hosts that kanon run reaches
examples/           m0-spine.kan, m1-spine.kan and reactor-realpath.kan
runtime/            shared reactor.kan, Node host reactor.mjs and run.mjs CLI
meta/               Lean metatheory, constructions and regression proofs
test/               main.ml, wasm.ml, sl_surface.ml, sys_io.ml,
                    fixtures/*.kan, golden/*.checked, golden/*.erased,
                    golden/*.wat, neg/*.kan, corpus/m1-corpus.kan,
                    agreement/*.kan
dev/                the runners, the gate scripts and the logs
```

## Build and test

The circuit reader accepts finite constructor trees and matches on their
acyclic global aliases. It counts arithmetic in leaf branches, multiplies
by the tree height only when a branch reads a field of its own
constructor, and rejects unknown or computed fields. See [CIRCUIT-BOUNDS.md](dev/CIRCUIT-BOUNDS.md)
for the supported fragment and regression evidence.

The OCaml toolchain is in the zxcaml-p1 opam switch, which is not on the
default PATH.  Two runner scripts add it and set the root, so you can call
them from any directory:

```
zsh dev/dunecho.sh build          # build, warnings are errors
zsh dev/dune.sh clean             # remove _build
zsh dev/carry-check.sh            # the carried files match the pin
zsh dev/r0-count.sh               # spec-count agrees with SPEC.md
zsh dev/encoder-subset.sh         # the goldens hold no opcode past SPEC.md
zsh dev/house.sh                  # the house rules over lib, surface, bin,
                                  # test, wasm and dev
zsh dev/r0-audit.sh               # no shape name outside its four files
zsh dev/trusted-lines.sh          # the kernel and the encoder line bounds
zsh dev/gates.sh                  # the whole gate battery, every leg
_build/default/test/main.exe test               # the kernel suite
_build/default/test/wasm.exe test               # the emission suite
node dev/reactor-test.mjs         # compiled module ABI, byte literals and
                                  # realpath CLI integration
node --test dev/runtime-test.mjs  # OS operations, process cleanup and
                                  # interruption status
```

Each script finds the repository root from its own path, so a copy of the
tree builds and checks itself.

## Gates

`zsh dev/gates.sh` runs the M1 battery, including the carried M0 legs.
Every leg prints one
`PASS LEG` line, or one `FAIL LEG` line and then the output that the leg
captured.  BUILD is the one leg that ends the run when it fails, because
every later leg reads the build it makes.  Every other leg runs even
when an earlier leg failed, so one run names every failing leg.  The
twenty-seven legs, in order:

```
BUILD            dev/dunecho.sh build prints 0 errors, 0 warnings
CARRY            the carried files still match the pin
R0-COUNT         kanon spec-count agrees with SPEC.md
R0-AUDIT         no shape name outside the four files that own it
SUITE-KERNEL     test/main.exe prints SUITE-KERNEL OK
SUITE-WASM       test/wasm.exe prints SUITE-WASM OK
ENCODER-SUBSET   the goldens hold no opcode past SPEC.md section 8
AXIOMS           b08 discloses Bit and the spine discloses nothing
M0-E2E           check, emit, wasm-opt, kernel and both hosts on the spine
M0-TIME          the median of the spine's run stays under the bound
M0-RATIO         corpus check time per line against tot's frozen baseline
TRUSTED-LINES    the kernel eight and the encoder stay under their bounds
CIRCUIT          the circuit rows of the mu fixtures against their bounds
ZK               the zk pack, its circuit rows and disclosure, against goldens
FHC              the fhc pack, its circuit rows and disclosure, against goldens
MPC              the mpc pack, its circuit rows and disclosure, against goldens
HOST             three compiled host programs and the compiled instance check
HOST-NAT         exact host naturals in the compiled twin and across the bytes
DENOMINATORS     dev/denominators.json matches its sha256 row
HOUSE            the house rules over lib, surface, bin, test, wasm and dev
PIN              PIN, vendor/tot and the pin worktree name one sha
POSITIVITY       all positive mu fixtures and the nonpositive rejection
M1-CORPUS        the 1000-line corpus, through check and all runtime hosts
M1-SUITE         feature ledger, negative twins, One, Nat and surface cases
AGREEMENT        5445 unary witnesses and 2000 independent full-range cases
REACTOR          compiled module ABI, byte literals and realpath CLI integration
RUNTIME          OS operations, process cleanup and interruption status
```

Several verdict lines include observations, such as `main=521`, timing
samples, the normalized ratio or agreement case counts.  Agreement is
finite test evidence, not a general arithmetic or compiler theorem.

After the last leg the script prints the MEASURE block, one line per leg
in the same order:

```
MEASURE BUILD tier=SLOW elapsed_ms=159.862 exit=0
```

The tier is the hang ceiling that the leg runs under: FAST is 10 seconds,
MED 30, SLOW 120 and SUITE 300.  `elapsed_ms` comes from the zsh clock, which
resolves microseconds.  The script then prints `GATES-OK` and exits 0,
or `GATES-FAIL` and exits 1.

The M0-TIME bound is 150 ms, applied to the median of three five-run
medians.  The timed command is the driver's whole run path over the M0
spine: check, erase, emit, node and wasmtime.  `wasm-opt` remains outside
that timing.  M1-CORPUS separately times the complete corpus path,
including module validation, against 713 ms.

M0-RATIO is binding at M1 with a bound of 2.000.  It compares the median
of five checks of the 1000-line corpus, per line, with the frozen tot
baseline of 103.662 ms over 8138 lines.  The original timing is in
dev/denominators.json and the dated normalization in
dev/denominators-m1.json.  These bounds are fixed in dev/gates.sh.

Work files live under `.gatework/gates/`, which .gitignore holds.

## Carried code

lib/level.ml, lib/level.mli, lib/quantity.ml, lib/literal.ml,
lib/global.ml, lib/budget.ml and lib/budget.mli come from tot at the sha
in PIN.  Each starts with a comment line that names its origin and its
delta.  dev/CARRIED.md holds the diff line count for each one, and
dev/carry-check.sh recomputes them.

## License

MIT OR Apache-2.0.  See LICENSE-MIT and LICENSE-APACHE.
