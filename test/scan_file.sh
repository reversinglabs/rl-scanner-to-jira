#! /bin/bash

source ~/.envfile_rl-scanner

export RLSECURE_ENCODED_LICENSE
export RLSECURE_SITE_KEY

main()
{
    local path="$1"

    [ -z "${path}" ] && {
        echo "FATAL: no file path provided to scan" >&2
        exit 101
    }

    [ ! -f "${path}" ] && {
        echo "FATAL: we need a path to a single file, '$path' is no file" >&2
        exit 101
    }

    local path=$(
        realpath "${path}"
    )

    local dir=$(
        dirname "${path}"
    )

    local file=$(
        basename "${path}"
    )

    rm -rf report && mkdir report # report dir must be empty

    docker run --rm \
        -u $(id -u):$(id -g) \
        -e RLSECURE_ENCODED_LICENSE \
        -e RLSECURE_SITE_KEY \
        -v "${dir}:/packages:ro" \
        -v "$(pwd)/report:/report" \
        reversinglabs/rl-scanner:latest \
            rl-scan \
                --package-path=/packages/"${file}" \
                --report-path=/report \
                --report-format=all

    # bundle the whole html tree so we can upload it as one file
    local d="$(pwd)/report/rl-html/"
    [ -d "${d}" ] && {
        ( cd "${d}"; zip -r ../rl-sdlc.zip . )
    }
}

main $*
