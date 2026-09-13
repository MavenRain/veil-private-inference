#!/bin/zsh
# dev/gates.sh
# The M1 gate battery: every carried and new leg of plan section 9, in the order the
# plan writes them.  Example:
#   zsh /Users/oobi/Documents/kanon/dev/gates.sh
#
# Each leg prints one PASS or FAIL line.  A FAIL adds the leg's captured
# output under its line.  BUILD is the one leg that ends the run, because
# every later leg reads the build.  Every other leg runs even when an
# earlier one failed, so one run names every failing leg (SE-D7).  After
# the last leg the script prints the MEASURE block, one line per leg in
# the order above, then GATES-OK and exit 0, or GATES-FAIL and exit 1.
#
# SA-D7: the root comes from this script's own path, so a copy of the
# repository under a scratch directory gates itself.
#
# The script also runs one leg alone, which is how the watchdog wraps a
# leg whose body is a shell function:
#   zsh dev/gates.sh --leg e2e

set -u

# The user shell startup files add a chpwd hook that reads an unset
# parameter.  Under set -u that hook fails and cd inherits its non-zero
# status, so the hooks are cleared before any cd.
chpwd_functions=()
unfunction chpwd 2>/dev/null

# EPOCHREALTIME carries microseconds, which is the resolution gate_timed
# reports in milliseconds (SE-D6).
zmodload zsh/datetime

SELF=${0:A}
ROOT=${0:A:h}/..
ROOT=${ROOT:A}
DRIVER=$ROOT/_build/default/bin/kanon.exe
SPINE=$ROOT/examples/m0-spine.kan
WORK=$ROOT/.gatework/gates
MEASURE_FILE=$WORK/measure.txt

# The pin worktree is read, never written.  It sits beside the repository
# by default, and the caller may name another path.
PIN_WORKTREE=${KANON_PIN_WORKTREE:-/Users/oobi/Documents/kan-lang-tot-pin}

# The M0-TIME bound in milliseconds.  Plan section 9 names the bound and
# correction C1 ratifies it at 150, with the resolution in milliseconds.
# No agent moves this number.
M0_TIME_MS=150
# D-M1-6 and Stage L section 9: these are binding, never environment overrides.
M0_RATIO=2.000
M1_CORPUS_MS=713

# The watchdog.  GNU coreutils ships timeout as gtimeout on stock macOS.
watchdog=""
if command -v timeout > /dev/null 2>&1; then
  watchdog=timeout
elif command -v gtimeout > /dev/null 2>&1; then
  watchdog=gtimeout
fi

if [[ -z $watchdog ]]; then
  print -r -- "FAIL-WATCHDOG (no timeout or gtimeout on PATH)"
  print -r -- "GATES-FAIL"
  exit 1
fi

# The named tiers, in seconds.  A tier is a hang ceiling, not a budget:
# a leg that grows from one second to nine stays green at FAST and shows
# the growth in the MEASURE block.  These four lines hold every numeric
# watchdog literal in this file.
FAST=10
MED=30
SLOW=120
SUITE=300

# gate_timed TIER NAME CMD...
# Runs one leg under the named tier, records the elapsed wall time in
# milliseconds, and forwards the leg's output and exit code unchanged.
# It adds no policy:  a green leg stays green and a red leg stays red.
gate_timed () {
  local tier=$1
  local name=$2
  shift 2
  local seconds=${(P)tier}
  local t0=$EPOCHREALTIME
  local out
  out=$("$watchdog" "$seconds" "$@" 2>&1)
  local code=$?
  local t1=$EPOCHREALTIME
  printf 'MEASURE %s tier=%s elapsed_ms=%.3f exit=%d\n' \
    "$name" "$tier" "$(( (t1 - t0) * 1000 ))" "$code" >> $MEASURE_FILE
  print -r -- "$out"
  return $code
}

# --- the leg bodies that need more than one command -------------------
#
# Each one prints its own PASS or FAIL line, because its verdict line
# carries a value.  The battery below runs them through the watchdog as
# "zsh dev/gates.sh --leg NAME".

# AXIOMS.  b08 postulates one name and the spine postulates none, so the
# leg reads both ends of the disclosure (SE-D11).
leg_axioms () {
  local b08=$ROOT/test/fixtures/b08-axiom-disclosure.kan
  local out1 code1 out2 code2
  out1=$($DRIVER axioms $b08 2>&1)
  code1=$?
  out2=$($DRIVER axioms $SPINE 2>&1)
  code2=$?
  if [[ $code1 -eq 0 && $out1 == "Bit" && $code2 -eq 0 && -z $out2 ]]; then
    print -r -- "PASS AXIOMS"
    return 0
  fi
  print -r -- "b08 exit=$code1 out=[$out1]"
  print -r -- "spine exit=$code2 out=[$out2]"
  print -r -- "FAIL AXIOMS"
  return 1
}

# M0-E2E.  The spine goes through check, emit, wasm-opt, the kernel and
# the two hosts, and the three answers must agree with the promise line
# the spine writes at its top.
leg_e2e () {
  local dir=$WORK/e2e
  rm -rf $dir
  mkdir -p $dir
  local out code
  out=$($DRIVER check $SPINE 2>&1)
  code=$?
  if [[ $code -ne 0 ]]; then
    print -r -- "check exit=$code out=[$out]"
    print -r -- "FAIL M0-E2E"
    return 1
  fi
  out=$($DRIVER emit $SPINE -o $dir/m0-spine.wasm --export main 2>&1)
  code=$?
  if [[ $code -ne 0 ]]; then
    print -r -- "emit exit=$code out=[$out]"
    print -r -- "FAIL M0-E2E"
    return 1
  fi
  out=$(wasm-opt $dir/m0-spine.wasm -S -o $dir/m0-spine.wat \
    --enable-gc --enable-reference-types --enable-tail-call \
    --enable-exception-handling 2>&1)
  code=$?
  if [[ $code -ne 0 ]]; then
    print -r -- "wasm-opt exit=$code out=[$out]"
    print -r -- "FAIL M0-E2E"
    return 1
  fi
  local kernel kcode hosts hcode promise lines
  kernel=$($DRIVER run $SPINE --export main --host kernel 2>&1)
  kcode=$?
  hosts=$($DRIVER run $SPINE --export main --host both 2>&1)
  hcode=$?
  promise=$(rg -N -o -- '-- main is [0-9]+' $SPINE | head -1 | awk '{ print $4 }')
  lines=$(wc -l < $SPINE | tr -d ' ')
  if [[ $kcode -eq 0 && $hcode -eq 0 && -n $promise && $kernel == $hosts \
    && $kernel == $promise && $lines -ge 200 ]]; then
    print -r -- "PASS M0-E2E main=$kernel"
    return 0
  fi
  print -r -- "kernel exit=$kcode out=[$kernel]"
  print -r -- "hosts exit=$hcode out=[$hosts]"
  print -r -- "promise=[$promise] lines=$lines"
  print -r -- "FAIL M0-E2E"
  return 1
}

# M0-TIME retains the whole driver path and SE-D9's wasm-opt exclusion.
# SL-D10: force five runs for each of three benches, print their spread,
# and compare the median of their medians against the unchanged bound.
leg_time () {
  python3 -P $ROOT/dev/m1-gates.py time --root $ROOT --bound $M0_TIME_MS
}

# SL-D11: the binding ratio reads the 1000-line corpus, the frozen
# 103.662 ms denominator and the separately dated 8138-line normalization.
# Comparison uses the unrounded ratio; printed precision is six decimals.
leg_ratio () {
  python3 -P $ROOT/dev/m1-gates.py ratio --root $ROOT --bound $M0_RATIO
}

leg_positivity () {
  python3 -P $ROOT/dev/m1-gates.py positivity --root $ROOT
}

leg_corpus () {
  python3 -P $ROOT/dev/m1-gates.py corpus --root $ROOT --bound $M1_CORPUS_MS
}

leg_m1_suite () {
  python3 -P $ROOT/dev/m1-gates.py m1-suite --root $ROOT
}

# SL-D14: never pass --only or --mutation in the permanent battery.
# Both approved finite sets, their round trips, goldens and exact host
# observations remain mandatory under the existing SUITE watchdog.
leg_agreement () {
  python3 -P $ROOT/dev/agreement.py --root $ROOT --evidence $WORK/agreement
  local code=$?
  if [[ $code -eq 0 ]]; then
    print -r -- "PASS AGREEMENT cases=7445 unary=5445 full-range=2000"
    return 0
  fi
  print -r -- "FAIL AGREEMENT"
  return 1
}

# DENOMINATORS.  shasum reads the row of DENOMINATORS.sha256 relative to
# dev/, so the check runs inside that directory.
leg_denominators () {
  local out code
  out=$(cd $ROOT/dev && shasum -a 256 -c DENOMINATORS.sha256 2>&1)
  code=$?
  if [[ $code -eq 0 && $out == "denominators.json: OK" ]]; then
    print -r -- "$out"
    print -r -- "PASS DENOMINATORS"
    return 0
  fi
  print -r -- "shasum exit=$code out=[$out]"
  print -r -- "FAIL DENOMINATORS"
  return 1
}

# PIN.  The PIN file, the vendored submodule and the pin worktree name
# one sha, and the worktree carries no change.  Every command reads;
# --no-optional-locks keeps git from writing an index in the worktree.
leg_pin () {
  local pinfile vendor worktree porcelain
  pinfile=$(cat $ROOT/PIN 2>&1 | tr -d ' \t\n')
  vendor=$(git -C $ROOT/vendor/tot --no-optional-locks rev-parse --short HEAD 2>&1)
  worktree=$(git -C $PIN_WORKTREE --no-optional-locks rev-parse --short HEAD 2>&1)
  porcelain=$(git -C $PIN_WORKTREE --no-optional-locks status --porcelain 2>&1)
  if [[ $pinfile == $vendor && $vendor == $worktree && -z $porcelain ]]; then
    print -r -- "PASS PIN sha=$pinfile"
    return 0
  fi
  print -r -- "PINfile=$pinfile vendor=$vendor worktree=$worktree"
  print -r -- "pin-porcelain=[$porcelain]"
  print -r -- "FAIL PIN"
  return 1
}

# CIRCUIT.  The D-8 circuit spine: one line per definition, either
# "NAME: depth D" or "NAME: refused: HEAD".  The verb exits 1 when the
# file holds a refused definition, which this file does by design, so
# the leg reads stdout only and ignores the exit code.  A timeout wraps
# the run when the host has one, because a lost refusal shows up as a
# hang, not as a wrong line.
#
# R-W1-10 for the reader regressions: the exit code of
# circuit_bounds.exe answers against the length of its own case list, so
# a deleted case still exits 0.  The leg reads the count line and holds
# it against the intended count below.  Raise BOUNDS_EXPECT with the
# case list, never to make a red leg green.
#
# The leg also holds the circuit rows of two older fixtures whose fields
# are closed data of another shape, because the rule for a field of an
# introduction at SMu decides whether those rows read a depth or a
# refusal.
BOUNDS_EXPECT='CIRCUIT-BOUNDS 18/18'
CIRCUIT_FIXTURES=(mu-dependent-layout one-fields)
leg_circuit () {
  local out delta bounds name
  local -a tmo
  tmo=(timeout 20)
  if ! command -v timeout > /dev/null 2>&1; then
    tmo=()
  fi
  mkdir -p $WORK || return 9
  $tmo $ROOT/_build/default/test/circuit_bounds.exe > $WORK/circuit-bounds.out 2>&1
  if [[ $? -ne 0 ]]; then
    cat $WORK/circuit-bounds.out
    print -r -- "FAIL CIRCUIT"
    return 1
  fi
  bounds=$(rg -N -- '^CIRCUIT-BOUNDS [0-9]+/[0-9]+$' $WORK/circuit-bounds.out)
  if [[ $bounds != $BOUNDS_EXPECT ]]; then
    cat $WORK/circuit-bounds.out
    print -r -- "circuit: expected [$BOUNDS_EXPECT], read [$bounds]"
    print -r -- "FAIL CIRCUIT"
    return 1
  fi
  for name in $CIRCUIT_FIXTURES; do
    $tmo $DRIVER circuit $ROOT/test/fixtures/$name.kan > $WORK/circuit-$name.out 2>&1
    delta=$(diff -u $ROOT/test/golden/circuit-$name.circuit $WORK/circuit-$name.out 2>&1)
    if [[ -n $delta || ! -s $WORK/circuit-$name.out ]]; then
      print -r -- "$delta"
      print -r -- "circuit: fixture $name"
      print -r -- "FAIL CIRCUIT"
      return 1
    fi
  done
  $tmo $DRIVER circuit $ROOT/test/circuit-spine.kan > $WORK/circuit-spine.out 2>&1
  out=$(cat $WORK/circuit-spine.out)
  delta=$(diff -u $ROOT/test/golden/circuit-spine.circuit $WORK/circuit-spine.out 2>&1)
  if [[ -z $delta && -s $WORK/circuit-spine.out ]]; then
    print -r -- "PASS CIRCUIT lines=$(print -r -- "$out" | wc -l | tr -d ' ') $bounds"
    return 0
  fi
  print -r -- "$delta"
  print -r -- "FAIL CIRCUIT"
  return 1
}

# ZK.  The veil D-9 zk pack over test/shapes/zk-pack.kan reads three
# ways: the checked form, the D-8 circuit spine and the D-13 disclosure,
# each against its golden.  The "circuit" verb exits 1 on a refused row
# by design, and this file holds one, so the leg reads stdout and
# ignores the exit code.  R-W1-10: an empty golden or an empty driver
# output is a FAIL, because an empty match is not a pass.
leg_zk () {
  local src=$ROOT/test/shapes/zk-pack.kan
  local part delta lines
  local -a tmo
  tmo=(timeout 20)
  if ! command -v timeout > /dev/null 2>&1; then
    tmo=()
  fi
  mkdir -p $WORK || return 9
  $tmo $DRIVER check --print $src > $WORK/zk-pack.checked 2>&1
  $tmo $DRIVER circuit $src > $WORK/zk-pack.circuit 2>&1
  $tmo $DRIVER axioms $src > $WORK/zk-pack.axioms 2>&1
  for part in checked circuit axioms; do
    if [[ ! -s $ROOT/test/golden/zk-pack.$part ]]; then
      print -r -- "zk: the golden test/golden/zk-pack.$part is empty"
      print -r -- "FAIL ZK"
      return 1
    fi
    if [[ ! -s $WORK/zk-pack.$part ]]; then
      print -r -- "zk: the driver wrote nothing for $part"
      print -r -- "FAIL ZK"
      return 1
    fi
    delta=$(diff -u $ROOT/test/golden/zk-pack.$part $WORK/zk-pack.$part 2>&1)
    if [[ -n $delta ]]; then
      print -r -- "$delta"
      print -r -- "FAIL ZK"
      return 1
    fi
  done
  lines=$(cat $WORK/zk-pack.checked $WORK/zk-pack.circuit $WORK/zk-pack.axioms \
    | wc -l | tr -d ' ')
  print -r -- "PASS ZK lines=$lines"
  return 0
}

# FHC.  The veil D-10 and D-11 fhc pack over test/shapes/fhc-pack.kan
# reads three ways: the checked form, the D-8 circuit spine and the D-13
# disclosure, each against its golden.  The "circuit" verb exits 1 on a
# refused row by design, and this file holds three of them, so the leg
# reads stdout and ignores the exit code.  R-W1-10: an empty golden or an
# empty driver output is a FAIL, because an empty match is not a pass.
leg_fhc () {
  local src=$ROOT/test/shapes/fhc-pack.kan
  local part delta lines
  local -a tmo
  tmo=(timeout 20)
  if ! command -v timeout > /dev/null 2>&1; then
    tmo=()
  fi
  mkdir -p $WORK || return 9
  $tmo $DRIVER check --print $src > $WORK/fhc-pack.checked 2>&1
  $tmo $DRIVER circuit $src > $WORK/fhc-pack.circuit 2>&1
  $tmo $DRIVER axioms $src > $WORK/fhc-pack.axioms 2>&1
  for part in checked circuit axioms; do
    if [[ ! -s $ROOT/test/golden/fhc-pack.$part ]]; then
      print -r -- "fhc: the golden test/golden/fhc-pack.$part is empty"
      print -r -- "FAIL FHC"
      return 1
    fi
    if [[ ! -s $WORK/fhc-pack.$part ]]; then
      print -r -- "fhc: the driver wrote nothing for $part"
      print -r -- "FAIL FHC"
      return 1
    fi
    delta=$(diff -u $ROOT/test/golden/fhc-pack.$part $WORK/fhc-pack.$part 2>&1)
    if [[ -n $delta ]]; then
      print -r -- "$delta"
      print -r -- "FAIL FHC"
      return 1
    fi
  done
  lines=$(cat $WORK/fhc-pack.checked $WORK/fhc-pack.circuit $WORK/fhc-pack.axioms \
    | wc -l | tr -d ' ')
  print -r -- "PASS FHC lines=$lines"
  return 0
}

# V1 wave 3, D-12.  The SMpc pack.  The leg reads test/shapes/mpc-pack.kan
# three ways: the checked form, the D-8 circuit spine and the D-13
# disclosure, each against its golden.  The "circuit" verb exits 1 on a
# refused row by design, and this file holds three of them, so the leg
# reads stdout and ignores the exit code.  R-W1-10: an empty golden or an
# empty driver output is a FAIL, because an empty match is not a pass.
leg_mpc () {
  local src=$ROOT/test/shapes/mpc-pack.kan
  local part delta lines
  local -a tmo
  tmo=(timeout 20)
  if ! command -v timeout > /dev/null 2>&1; then
    tmo=()
  fi
  mkdir -p $WORK || return 9
  $tmo $DRIVER check --print $src > $WORK/mpc-pack.checked 2>&1
  $tmo $DRIVER circuit $src > $WORK/mpc-pack.circuit 2>&1
  $tmo $DRIVER axioms $src > $WORK/mpc-pack.axioms 2>&1
  for part in checked circuit axioms; do
    if [[ ! -s $ROOT/test/golden/mpc-pack.$part ]]; then
      print -r -- "mpc: the golden test/golden/mpc-pack.$part is empty"
      print -r -- "FAIL MPC"
      return 1
    fi
    if [[ ! -s $WORK/mpc-pack.$part ]]; then
      print -r -- "mpc: the driver wrote nothing for $part"
      print -r -- "FAIL MPC"
      return 1
    fi
    delta=$(diff -u $ROOT/test/golden/mpc-pack.$part $WORK/mpc-pack.$part 2>&1)
    if [[ -n $delta ]]; then
      print -r -- "$delta"
      print -r -- "FAIL MPC"
      return 1
    fi
  done
  lines=$(cat $WORK/mpc-pack.checked $WORK/mpc-pack.circuit $WORK/mpc-pack.axioms \
    | wc -l | tr -d ' ')
  print -r -- "PASS MPC lines=$lines"
  return 0
}

# HOST.  V1 wave 4, D-15.  The three run programs of test/host/ reach the
# reactor ops.  "kanon build" links each program with runtime/reactor.kan,
# the Kanon twin, so the module has no import and dev/run-node.mjs prints
# the export "main".  The leg diffs that answer against the golden
# test/golden/NAME.run.  R-W1-10: an empty golden or an empty runner
# output is a FAIL, because an empty match is not a pass.
leg_host () {
  local src name delta out programs verdict
  local -a tmo
  tmo=(timeout 60)
  if ! command -v timeout > /dev/null 2>&1; then
    tmo=()
  fi
  mkdir -p $WORK || return 9
  programs=0
  for name in zk-pack fhc-pack mpc-pack; do
    src=$ROOT/test/host/$name.kan
    if [[ ! -s $ROOT/test/golden/$name.run ]]; then
      print -r -- "host: the golden test/golden/$name.run is empty"
      print -r -- "FAIL HOST"
      return 1
    fi
    if ! $tmo $DRIVER check $src > $WORK/$name.hostcheck 2>&1; then
      cat $WORK/$name.hostcheck
      print -r -- "host: check refused $name"
      print -r -- "FAIL HOST"
      return 1
    fi
    if ! $tmo $DRIVER build $ROOT/runtime/reactor.kan $src \
      -o $WORK/$name.host.wasm --export main > $WORK/$name.hostbuild 2>&1; then
      cat $WORK/$name.hostbuild
      print -r -- "host: build refused $name"
      print -r -- "FAIL HOST"
      return 1
    fi
    $tmo node $ROOT/dev/run-node.mjs $WORK/$name.host.wasm main \
      > $WORK/$name.hostrun 2>&1
    if [[ ! -s $WORK/$name.hostrun ]]; then
      print -r -- "host: the runner wrote nothing for $name"
      print -r -- "FAIL HOST"
      return 1
    fi
    delta=$(diff -u $ROOT/test/golden/$name.run $WORK/$name.hostrun 2>&1)
    if [[ -n $delta ]]; then
      print -r -- "$delta"
      print -r -- "FAIL HOST"
      return 1
    fi
    programs=$(( programs + 1 ))
  done
  if ! $tmo node $ROOT/dev/zk-instance-test.mjs $DRIVER > $WORK/zk-instance.hostrun 2>&1; then
    cat $WORK/zk-instance.hostrun
    print -r -- "FAIL HOST"
    return 1
  fi
  # R-W1-10 again: the leg reads the verdict line only, so an added passing
  # case or a warning line on either stream cannot turn the leg red. The leg
  # is red when the process exits nonzero, when no verdict line is present,
  # or when the two counts of the verdict line differ.
  verdict=''
  while IFS= read -r out; do
    if [[ $out == 'ZK-INSTANCE '<->'/'<-> ]]; then
      verdict=${out#ZK-INSTANCE }
    fi
  done < $WORK/zk-instance.hostrun
  if [[ -z $verdict ]]; then
    cat $WORK/zk-instance.hostrun
    print -r -- "host: the compiled check printed no ZK-INSTANCE verdict line"
    print -r -- "FAIL HOST"
    return 1
  fi
  if [[ ${verdict%/*} != ${verdict#*/} ]]; then
    cat $WORK/zk-instance.hostrun
    print -r -- "host: the compiled check passed $verdict cases"
    print -r -- "FAIL HOST"
    return 1
  fi
  print -r -- "PASS HOST programs=$programs zk-instance=$verdict"
  return 0
}

# The host natural harness compiles test/host/host-nat.kan and
# test/host/nat-bytes.kan with the reactor and runs the byte cases through
# the JavaScript host.  R-W1-10, as in leg_host: the leg reads the verdict
# line only, so an added passing case or a warning line on either stream
# cannot turn the leg red.  The leg is red when the process exits nonzero,
# when no verdict line is present, or when the two counts differ.
leg_host_nat () {
  local out verdict
  local -a tmo
  tmo=(timeout 60)
  if ! command -v timeout > /dev/null 2>&1; then
    tmo=()
  fi
  mkdir -p $WORK || return 9
  if ! $tmo node $ROOT/dev/host-nat-test.mjs $DRIVER > $WORK/host-nat.hostrun 2>&1; then
    cat $WORK/host-nat.hostrun
    print -r -- "FAIL HOST-NAT"
    return 1
  fi
  verdict=''
  while IFS= read -r out; do
    if [[ $out == 'HOST-NAT '<->'/'<-> ]]; then
      verdict=${out#HOST-NAT }
    fi
  done < $WORK/host-nat.hostrun
  if [[ -z $verdict ]]; then
    cat $WORK/host-nat.hostrun
    print -r -- "host-nat: the harness printed no HOST-NAT verdict line"
    print -r -- "FAIL HOST-NAT"
    return 1
  fi
  if [[ ${verdict%/*} != ${verdict#*/} ]]; then
    cat $WORK/host-nat.hostrun
    print -r -- "host-nat: the harness passed $verdict checks"
    print -r -- "FAIL HOST-NAT"
    return 1
  fi
  print -r -- "PASS HOST-NAT checks=$verdict"
  return 0
}

mkdir -p $WORK || exit 9

# One leg alone, which is how the watchdog reaches a leg body.
if [[ $# -ge 2 && $1 == "--leg" ]]; then
  case $2 in
    axioms) leg_axioms; exit $? ;;
    e2e) leg_e2e; exit $? ;;
    time) leg_time; exit $? ;;
    ratio) leg_ratio; exit $? ;;
    positivity) leg_positivity; exit $? ;;
    corpus) leg_corpus; exit $? ;;
    m1-suite) leg_m1_suite; exit $? ;;
    agreement) leg_agreement; exit $? ;;
    denominators) leg_denominators; exit $? ;;
    pin) leg_pin; exit $? ;;
    circuit) leg_circuit; exit $? ;;
    zk) leg_zk; exit $? ;;
    fhc) leg_fhc; exit $? ;;
    mpc) leg_mpc; exit $? ;;
    host) leg_host; exit $? ;;
    host-nat) leg_host_nat; exit $? ;;
    *) print -r -- "gates: unknown leg $2"; exit 64 ;;
  esac
fi

if [[ $# -ne 0 ]]; then
  print -r -- "usage: zsh dev/gates.sh [--leg NAME]"
  exit 64
fi

: > $MEASURE_FILE || exit 9
fail=0

# leg TIER NAME ORACLE CMD...
#   ORACLE is a ripgrep pattern that the leg's output must hold when the
#   leg exits 0.  The word SELF means the leg prints its own verdict
#   line, because that line carries a value, and its whole output
#   belongs on stdout.
leg () {
  local tier=$1
  local name=$2
  local oracle=$3
  shift 3
  local out code
  out=$(gate_timed $tier $name "$@")
  code=$?
  if [[ $oracle == "SELF" ]]; then
    print -r -- "$out"
    if [[ $code -eq 0 ]]; then
      return 0
    fi
    if ! print -r -- "$out" | rg -q -- "^FAIL $name"; then
      print -r -- "FAIL $name"
    fi
    fail=1
    return 1
  fi
  if [[ $code -eq 0 ]] && print -r -- "$out" | rg -q -- "$oracle"; then
    print -r -- "PASS $name"
    return 0
  fi
  print -r -- "FAIL $name"
  print -r -- "$out"
  fail=1
  return 1
}

# The legs, in the order of plan section 9.  BUILD ends the run when it
# fails, because every later leg reads the build it makes.
if ! leg SLOW BUILD '0 errors, 0 warnings' zsh $ROOT/dev/dunecho.sh build; then
  print -r -- ""
  cat $MEASURE_FILE
  print -r -- ""
  print -r -- "GATES-FAIL"
  exit 1
fi

leg MED CARRY '^CARRY-OK$' zsh $ROOT/dev/carry-check.sh
leg FAST R0-COUNT '^R0-COUNT OK$' zsh $ROOT/dev/r0-count.sh
leg FAST R0-AUDIT '^R0-AUDIT OK$' zsh $ROOT/dev/r0-audit.sh
leg SUITE SUITE-KERNEL '^SUITE-KERNEL OK$' \
  $ROOT/_build/default/test/main.exe $ROOT/test
leg SUITE SUITE-WASM '^SUITE-WASM OK$' \
  $ROOT/_build/default/test/wasm.exe $ROOT/test
leg FAST ENCODER-SUBSET '^ENCODER-SUBSET OK$' \
  zsh $ROOT/dev/encoder-subset.sh $ROOT
leg MED AXIOMS SELF zsh $SELF --leg axioms
leg SLOW M0-E2E SELF zsh $SELF --leg e2e
leg SLOW M0-TIME SELF zsh $SELF --leg time
leg SLOW M0-RATIO SELF zsh $SELF --leg ratio
leg FAST TRUSTED-LINES '^TRUSTED-LINES kernel=[0-9]+/[0-9]+ encoder=[0-9]+/[0-9]+ OK$' \
  zsh $ROOT/dev/trusted-lines.sh $ROOT
leg FAST CIRCUIT SELF zsh $SELF --leg circuit
leg FAST ZK SELF zsh $SELF --leg zk
leg FAST FHC SELF zsh $SELF --leg fhc
leg FAST MPC SELF zsh $SELF --leg mpc
leg MED HOST SELF zsh $SELF --leg host
leg MED HOST-NAT SELF zsh $SELF --leg host-nat
leg MED PRIVATE-INFERENCE '^# fail 0$' \
  node --test --test-reporter=tap $ROOT/dev/private-inference-test.mjs
leg MED DENOMINATORS SELF zsh $SELF --leg denominators
leg MED HOUSE '^HOUSE OK$' zsh $ROOT/dev/house.sh $ROOT
leg FAST PIN SELF zsh $SELF --leg pin
leg SUITE POSITIVITY SELF zsh $SELF --leg positivity
leg SLOW M1-CORPUS SELF zsh $SELF --leg corpus
leg SUITE M1-SUITE SELF zsh $SELF --leg m1-suite
leg SUITE AGREEMENT SELF zsh $SELF --leg agreement
# The reactor slice legs.  REACTOR builds the reactor fixtures through the
# normal CLI and checks the module in Node.  RUNTIME runs the host runtime
# suite.  Both fit the MED tier, at about 2 s and about 3 s.
leg MED REACTOR '^reactor: [0-9]+ checks passed$' \
  node $ROOT/dev/reactor-test.mjs $ROOT/_build/default/bin/kanon.exe
leg MED RUNTIME '^# fail 0$' node --test --test-reporter=tap $ROOT/dev/runtime-test.mjs

print -r -- ""
cat $MEASURE_FILE
print -r -- ""

if [[ $fail -eq 0 ]]; then
  print -r -- "GATES-OK"
  exit 0
fi

print -r -- "GATES-FAIL"
exit 1
