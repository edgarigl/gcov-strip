#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_DIR="${SRC_DIR:-$ROOT/tests/cache/src}"
BUILD_DIR="${BUILD_DIR:-$ROOT/tests/cache/build}"
INSTALL_DIR="${INSTALL_DIR:-$ROOT/tests/cache/binutils}"
DOWNLOAD_URL_BASE="${DOWNLOAD_URL_BASE:-https://ftp.gnu.org/gnu/binutils}"
GCC_VERSIONS="${GCC_VERSIONS-9 10 11 12 13 14 15 16 17 18 19 20}"
BINUTILS_VERSIONS="${BINUTILS_VERSIONS-2.26 2.30 2.34 2.42 2.43.1 2.44 2.45 2.46.0}"
VARIANTS="${VARIANTS-5}"
BASELINE_READELF="${BASELINE_READELF-readelf}"
BASELINE_NAME="${BASELINE_NAME-host}"
REFERENCE_GCC_VERSION="${REFERENCE_GCC_VERSION-}"
REFERENCE_VARIANT="${REFERENCE_VARIANT-5}"
REFERENCE_NAME="${REFERENCE_NAME-matrix-reference}"
JOBS="${JOBS-$(nproc)}"
PREP_JOBS="${PREP_JOBS-2}"
SUMMARY_CSV="${SUMMARY_CSV-$ROOT/tests/cache/check-readelf-matrix.csv}"

declare -A SUMMARY_STATUS
declare -A BINUTILS_OK_COUNT


record_summary() {
    local gcc_version="$1"
    local variant="$2"
    local status="$3"

    SUMMARY_STATUS["$gcc_version:$variant"]="$status"
}


append_csv() {
    local gcc_version="$1"
    local variant="$2"
    local binutils_version="$3"
    local status="$4"
    local detail="$5"

    printf '%s,%s,%s,%s,%s\n' \
        "$gcc_version" "$variant" "$binutils_version" "$status" "$detail" \
        >>"$SUMMARY_CSV"
}


print_summary_table() {
    local gcc_version
    local variant
    local status

    printf '\nSummary:\n'
    printf '%-8s' "gcc"
    for variant in $VARIANTS; do
        printf ' %-8s' "$variant"
    done
    printf '\n'

    for gcc_version in $GCC_VERSIONS; do
        if ! have_toolchain "$gcc_version"; then
            continue
        fi

        printf '%-8s' "gcc-$gcc_version"
        for variant in $VARIANTS; do
            status="${SUMMARY_STATUS["$gcc_version:$variant"]-skip}"
            printf ' %-8s' "$status"
        done
        printf '\n'
    done
}


record_binutils_ok() {
    local binutils_version="$1"
    local ok_count="${BINUTILS_OK_COUNT["$binutils_version"]-0}"

    BINUTILS_OK_COUNT["$binutils_version"]=$((ok_count + 1))
}


print_binutils_summary() {
    local binutils_version
    local ok_count

    printf '\nReadelf coverage:\n'
    printf '%-18s %s\n' "readelf" "ok-cases"
    ok_count="${BINUTILS_OK_COUNT["$BASELINE_NAME"]-0}"
    printf '%-18s %s\n' "$BASELINE_NAME" "$ok_count"

    for binutils_version in $BINUTILS_VERSIONS; do
        ok_count="${BINUTILS_OK_COUNT["$binutils_version"]-0}"
        printf '%-18s %s\n' "binutils-$binutils_version" "$ok_count"
    done
}

run_matrix_case() {
    local gcc_version="$1"
    local variant_flags="$2"
    local readelf_bin="$3"
    local output_cfg="$4"
    local log_path="$5"

    make -C "$ROOT" clean >/dev/null
    CC="gcc-$gcc_version" GCOV="gcov-$gcc_version" READELF="$readelf_bin" \
        CFLAGS="$variant_flags" \
        make -C "$ROOT" ctest >"$log_path" 2>&1
    cp "$ROOT/funcs-removed.cfg" "$output_cfg"
}


variant_flags() {
    local variant="$1"

    case "$variant" in
        g)
            printf '%s\n' "-Wall -O2 -g -ffunction-sections -fprofile-arcs -ftest-coverage"
            ;;
        gno-strict-dwarf)
            printf '%s\n' \
                "-Wall -O2 -g -ffunction-sections -fprofile-arcs -ftest-coverage -gno-strict-dwarf"
            ;;
        2|3|4|5)
            printf '%s\n' \
                "-Wall -O2 -g -ffunction-sections -fprofile-arcs -ftest-coverage -gdwarf-$variant"
            ;;
        5-gno-strict-dwarf)
            printf '%s\n' \
                "-Wall -O2 -g -ffunction-sections -fprofile-arcs -ftest-coverage -gdwarf-5 -gno-strict-dwarf"
            ;;
        5-gdwarf64)
            printf '%s\n' \
                "-Wall -O2 -g -ffunction-sections -fprofile-arcs -ftest-coverage -gdwarf-5 -gdwarf64"
            ;;
        5-gdwarf64-gno-strict-dwarf)
            printf '%s\n' \
                "-Wall -O2 -g -ffunction-sections -fprofile-arcs -ftest-coverage -gdwarf-5 -gdwarf64 -gno-strict-dwarf"
            ;;
        *)
            echo "unknown variant: $variant" >&2
            exit 1
            ;;
    esac
}


variant_name() {
    local variant="$1"

    case "$variant" in
        g)
            printf '%s\n' "-g"
            ;;
        gno-strict-dwarf)
            printf '%s\n' "-g -gno-strict-dwarf"
            ;;
        2|3|4|5)
            printf '%s\n' "-gdwarf-$variant"
            ;;
        5-gno-strict-dwarf)
            printf '%s\n' "-gdwarf-5 -gno-strict-dwarf"
            ;;
        5-gdwarf64)
            printf '%s\n' "-gdwarf-5 -gdwarf64"
            ;;
        5-gdwarf64-gno-strict-dwarf)
            printf '%s\n' "-gdwarf-5 -gdwarf64 -gno-strict-dwarf"
            ;;
    esac
}


variant_unsupported() {
    local log_path="$1"

    grep -Eq \
        "unrecognized .*gdwarf|dwarf version .*is not supported|unknown DWARF version|unrecognized .*gdwarf64|dwarf64.*not supported|sorry, unimplemented: 64-bit DWARF" \
        "$log_path"
}


have_toolchain() {
    local gcc_version="$1"

    command -v "gcc-$gcc_version" >/dev/null 2>&1 && \
        command -v "gcov-$gcc_version" >/dev/null 2>&1
}


find_reference_gcc_version() {
    local gcc_version
    local last_installed=""

    for gcc_version in $GCC_VERSIONS; do
        if have_toolchain "$gcc_version"; then
            last_installed="$gcc_version"
        fi
    done

    printf '%s\n' "$last_installed"
}


tool_version_line() {
    local tool="$1"

    "$tool" --version | head -n 1
}


if [ -n "$BINUTILS_VERSIONS" ]; then
    echo "== preparing readelf set ==" >&2
    make \
        -f "$ROOT/tests/binutils-cache.mk" \
        -j"$PREP_JOBS" \
        SRC_DIR="$SRC_DIR" \
        BUILD_DIR="$BUILD_DIR" \
        INSTALL_DIR="$INSTALL_DIR" \
        DOWNLOAD_URL_BASE="$DOWNLOAD_URL_BASE" \
        BINUTILS_VERSIONS="$BINUTILS_VERSIONS" \
        BUILD_JOBS="$JOBS" \
        all
fi

if [ -n "$REFERENCE_GCC_VERSION" ]; then
    global_reference_gcc="$REFERENCE_GCC_VERSION"
else
    global_reference_gcc="$(find_reference_gcc_version)"
fi

if [ -z "$global_reference_gcc" ]; then
    exit 0
fi

mkdir -p "$(dirname "$SUMMARY_CSV")"
printf '%s\n' "gcc,variant,binutils,status,detail" >"$SUMMARY_CSV"

global_reference_label="$(variant_name "$REFERENCE_VARIANT")"
global_reference_flags="$(variant_flags "$REFERENCE_VARIANT")"
global_reference_cfg="/tmp/funcs-removed-gcc-$global_reference_gcc-reference.cfg"
global_reference_log="/tmp/check-readelf-gcc-$global_reference_gcc-reference.log"

echo \
    "== $REFERENCE_NAME gcc-$global_reference_gcc " \
    "$global_reference_label =="
echo "   gcc: $(tool_version_line "gcc-$global_reference_gcc")"
if ! run_matrix_case \
    "$global_reference_gcc" \
    "$global_reference_flags" \
    "$BASELINE_READELF" \
    "$global_reference_cfg" \
    "$global_reference_log"; then
    cat "$global_reference_log"
    exit 1
fi

for gcc_version in $GCC_VERSIONS; do
    if ! have_toolchain "$gcc_version"; then
        continue
    fi

    for variant in $VARIANTS; do
        flags="$(variant_flags "$variant")"
        label="$(variant_name "$variant")"

        echo "== gcc-$gcc_version $label readelf matrix =="
        echo "   gcc: $(tool_version_line "gcc-$gcc_version")"

        baseline_cfg="/tmp/funcs-removed-gcc-$gcc_version-$variant-$BASELINE_NAME.cfg"
        baseline_log="/tmp/check-readelf-gcc-$gcc_version-$variant-$BASELINE_NAME.log"
        if ! run_matrix_case \
            "$gcc_version" \
            "$flags" \
            "$BASELINE_READELF" \
            "$baseline_cfg" \
            "$baseline_log"; then
            if variant_unsupported "$baseline_log"; then
                record_summary "$gcc_version" "$variant" "skip"
                append_csv "$gcc_version" "$variant" "$BASELINE_NAME" "skip" \
                    "unsupported"
                echo "skip gcc-$gcc_version $label" >&2
                continue
            fi
            record_summary "$gcc_version" "$variant" "fail"
            append_csv "$gcc_version" "$variant" "$BASELINE_NAME" "fail" \
                "baseline-build"
            cat "$baseline_log"
            exit 1
        fi

        if ! diff -u "$global_reference_cfg" "$baseline_cfg"; then
            record_summary "$gcc_version" "$variant" "fail"
            append_csv "$gcc_version" "$variant" "$BASELINE_NAME" "fail" \
                "global-mismatch"
            echo \
                "global config mismatch for gcc-$gcc_version $label: " \
                "$REFERENCE_NAME gcc-$global_reference_gcc " \
                "$global_reference_label"
            exit 1
        fi

        record_summary "$gcc_version" "$variant" "ok"
        append_csv "$gcc_version" "$variant" "$BASELINE_NAME" "ok" "baseline"
        record_binutils_ok "$BASELINE_NAME"

        for binutils_version in $BINUTILS_VERSIONS; do
            readelf_bin="$INSTALL_DIR/$binutils_version/bin/readelf"
            cfg="/tmp/funcs-removed-gcc-$gcc_version-$variant-binutils-$binutils_version.cfg"
            log_path="/tmp/check-readelf-gcc-$gcc_version-$variant-binutils-$binutils_version.log"

            echo "== gcc-$gcc_version $label binutils-$binutils_version =="
            if ! run_matrix_case \
                "$gcc_version" \
                "$flags" \
                "$readelf_bin" \
                "$cfg" \
                "$log_path"; then
                record_summary "$gcc_version" "$variant" "fail"
                append_csv "$gcc_version" "$variant" "$binutils_version" "fail" \
                    "matrix-build"
                cat "$log_path"
                exit 1
            fi

            if ! diff -u "$baseline_cfg" "$cfg"; then
                record_summary "$gcc_version" "$variant" "fail"
                append_csv "$gcc_version" "$variant" "$binutils_version" "fail" \
                    "baseline-mismatch"
                echo \
                    "readelf config mismatch for gcc-$gcc_version $label: " \
                    "$BASELINE_NAME vs binutils-$binutils_version"
                exit 1
            fi

            if ! diff -u "$global_reference_cfg" "$cfg"; then
                record_summary "$gcc_version" "$variant" "fail"
                append_csv "$gcc_version" "$variant" "$binutils_version" "fail" \
                    "global-mismatch"
                echo \
                    "global config mismatch for gcc-$gcc_version $label " \
                    "binutils-$binutils_version: $REFERENCE_NAME gcc-" \
                    "$global_reference_gcc $global_reference_label"
                exit 1
            fi

            append_csv "$gcc_version" "$variant" "$binutils_version" "ok" "match"
            record_binutils_ok "$binutils_version"
        done
    done
done

print_summary_table
print_binutils_summary
