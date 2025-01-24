# Feature option variables
PRE_COMMIT_VERSION="${VERSION:-"latest"}"

# Config variables
OPTIMIZE_PYTHON_BUILD_FROM_SOURCE="false"
ENABLE_SHARED_FROM_SOURCE="false"
PYTHON_INSTALL_PATH="/usr/local/python"
OVERRIDE_DEFAULT_PYTHON_VERSION="false"

USERNAME="${USERNAME:-"${_REMOTE_USER:-"automatic"}"}"
UPDATE_RC="true"

PYTHON_SOURCE_GPG_KEYS="64E628F8D684696D B26995E310250568 2D347EA6AA65421D FB9921286F5E1540 3A5CA953F73C700D 04C367C218ADD4FF 0EDDC5F26A45C816 6AF053F07D9DC8D2 C9BE28DEE6DF025C 126EB563A74B06BF D9866941EA5BBD71 ED9D77D5 A821E680E5FA6305"

KEYSERVER_PROXY="${HTTPPROXY:-"${HTTP_PROXY:-""}"}"

pkg_mgr_update() {
    case $ADJUSTED_ID in
        debian)
            if [ "$(find /var/lib/apt/lists/* | wc -l)" = "0" ]; then
                echo "Running apt-get update..."
                ${PKG_MGR_CMD} update -y
            fi
            ;;
        rhel)
            if [ ${PKG_MGR_CMD} = "microdnf" ]; then
                if [ "$(ls /var/cache/yum/* 2>/dev/null | wc -l)" = 0 ]; then
                    echo "Running ${PKG_MGR_CMD} makecache ..."
                    ${PKG_MGR_CMD} makecache
                fi
            else
                if [ "$(ls /var/cache/${PKG_MGR_CMD}/* 2>/dev/null | wc -l)" = 0 ]; then
                    echo "Running ${PKG_MGR_CMD} check-update ..."
                    set +e
                    ${PKG_MGR_CMD} check-update
                    rc=$?
                    if [ $rc != 0 ] && [ $rc != 100 ]; then
                        exit 1
                    fi
                    set -e
                fi
            fi
            ;;
    esac
}

# Checks if packages are installed and installs them if not
check_packages() {
    case ${ADJUSTED_ID} in
        debian)
            if ! dpkg -s "$@" > /dev/null 2>&1; then
                pkg_mgr_update
                ${INSTALL_CMD} "$@"
            fi
            ;;
        rhel)
            if ! rpm -q "$@" > /dev/null 2>&1; then
                pkg_mgr_update
                ${INSTALL_CMD} "$@"
            fi
            ;;
    esac
}

version_finder() {
    local cmd_base="$1"
    local version_flag="--version"
    
    version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }
    
    while IFS= read -r -d '' cmd_path; do
        local cmd=$(basename "$cmd_path")
        [[ $cmd =~ ^$cmd_base[0-9]+(\.[0-9]+)*$ ]] || continue
        
        if version=$(timeout 2s "$cmd" "$version_flag" 2>&1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+'); then
            if [ -z "${HIGHEST_VERSION:-}" ] || version_gt "$version" "$HIGHEST_VERSION"; then
                HIGHEST_VERSION="$version"
                HIGHEST_CMD="$cmd"
            elif [ "$version" = "$HIGHEST_VERSION" ]; then
                HIGHEST_CMD="$cmd"
            fi
        fi
    done < <(find ${PATH//:/ } -maxdepth 1 -executable -name "$cmd_base*" -print0 2>/dev/null)
    
    if [ -n "${HIGHEST_VERSION:-}" ]; then
        printf '%s\t%s\n' "$HIGHEST_CMD" "$HIGHEST_VERSION"
    else
        exit 1
    fi
}

# Use Oryx to install something using a partial version match
oryx_install() {
    local platform=$1
    local requested_version=$2
    local target_folder=${3:-none}
    local ldconfig_folder=${4:-none}
    echo "(*) Installing ${platform} ${requested_version} using Oryx..."
    check_packages jq
    # Soft match if full version not specified
    if [ "$(echo "${requested_version}" | grep -o "." | wc -l)" != "2" ]; then
        local version_list="$(oryx platforms --json | jq -r ".[] | select(.Name == \"${platform}\") | .Versions | sort | reverse | @tsv" | tr '\t' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$')"
        if [ "${requested_version}" = "latest" ] || [ "${requested_version}" = "current" ] || [ "${requested_version}" = "lts" ]; then
            requested_version="$(echo "${version_list}" | head -n 1)"
        else
            set +e
            requested_version="$(echo "${version_list}" | grep -E -m 1 "^${requested_version//./\\.}([\\.\\s]|$)")"
            set -e
        fi
        if [ -z "${requested_version}" ] || ! echo "${version_list}" | grep "^${requested_version//./\\.}$" > /dev/null 2>&1; then
            echo -e "(!) Oryx does not support ${platform} version $2\nValid values:\n${version_list}" >&2
            return 1
        fi
        echo "(*) Using ${requested_version} in place of $2."
    fi

    export ORYX_ENV_TYPE=vsonline-present ORYX_PREFER_USER_INSTALLED_SDKS=true ENABLE_DYNAMIC_INSTALL=true DYNAMIC_INSTALL_ROOT_DIR=/opt
    oryx prep --skip-detection --platforms-and-versions "${platform}=${requested_version}"
    local opt_folder="/opt/${platform}/${requested_version}"
    if [ "${target_folder}" != "none" ] && [ "${target_folder}" != "${opt_folder}" ]; then
        ln -s "${opt_folder}" "${target_folder}"
    fi
    # Update library path add to conf
    if [ "${ldconfig_folder}" != "none" ]; then
        echo "/opt/${platform}/${requested_version}/lib" >> "/etc/ld.so.conf.d/${platform}.conf"
        ldconfig
    fi
}

add_symlink() {
    if [[ ! -d "${CURRENT_PATH}" ]]; then
        ln -s -r "${INSTALL_PATH}" "${CURRENT_PATH}"
    fi

    if [ "${OVERRIDE_DEFAULT_PYTHON_VERSION}" = "true" ]; then
        if [[ $(ls -l ${CURRENT_PATH}) != *"-> ${INSTALL_PATH}"* ]] ; then
            rm "${CURRENT_PATH}"
            ln -s -r "${INSTALL_PATH}" "${CURRENT_PATH}"
        fi
    fi
}

install_using_oryx() {
    VERSION=$1
    INSTALL_PATH="${PYTHON_INSTALL_PATH}/${VERSION}"

    # Check if the specified Python version is already installed
    if [ -d "${INSTALL_PATH}" ]; then
        echo "(!) Python version ${VERSION} already exists."
    else
        # The python install root path may not exist, so create it
        mkdir -p "${PYTHON_INSTALL_PATH}"
        oryx_install "python" "${VERSION}" "${INSTALL_PATH}" "lib" || return 1

        ln -s "${INSTALL_PATH}/bin/idle3" "${INSTALL_PATH}/bin/idle"
        ln -s "${INSTALL_PATH}/bin/pydoc3" "${INSTALL_PATH}/bin/pydoc"
        ln -s "${INSTALL_PATH}/bin/python3-config" "${INSTALL_PATH}/bin/python-config"

        add_symlink
    fi
}

# Get the list of GPG key servers that are reachable
get_gpg_key_servers() {
    declare -A keyservers_curl_map=(
        ["hkp://keyserver.ubuntu.com"]="http://keyserver.ubuntu.com:11371"
        ["hkp://keyserver.ubuntu.com:80"]="http://keyserver.ubuntu.com"
        ["hkps://keys.openpgp.org"]="https://keys.openpgp.org"
        ["hkp://keyserver.pgp.com"]="http://keyserver.pgp.com:11371"
    )

    local curl_args=""
    local keyserver_reachable=false  # Flag to indicate if any keyserver is reachable

    if [ ! -z "${KEYSERVER_PROXY}" ]; then
        curl_args="--proxy ${KEYSERVER_PROXY}"
    fi

    for keyserver in "${!keyservers_curl_map[@]}"; do
        local keyserver_curl_url="${keyservers_curl_map[${keyserver}]}"
        if curl -s ${curl_args} --max-time 5 ${keyserver_curl_url} > /dev/null; then
            echo "keyserver ${keyserver}"
            keyserver_reachable=true
        else
            echo "(*) Keyserver ${keyserver} is not reachable." >&2
        fi
    done

    if ! $keyserver_reachable; then
        echo "(!) No keyserver is reachable." >&2
        exit 1
    fi
}

# Import the specified key in a variable name passed in as
receive_gpg_keys() {
    local keys=${!1}
    local keyring_args=""
    local gpg_cmd="gpg"
    if [ ! -z "$2" ]; then
        mkdir -p "$(dirname \"$2\")"
        keyring_args="--no-default-keyring --keyring $2"
    fi
    if [ ! -z "${KEYSERVER_PROXY}" ]; then
        keyring_args="${keyring_args} --keyserver-options http-proxy=${KEYSERVER_PROXY}"
    fi

    # Install curl
    if ! type curl > /dev/null 2>&1; then
        check_packages curl
    fi

    # Use a temporary location for gpg keys to avoid polluting image
    export GNUPGHOME="/tmp/tmp-gnupg"
    mkdir -p ${GNUPGHOME}
    chmod 700 ${GNUPGHOME}
    echo -e "disable-ipv6\n$(get_gpg_key_servers)" > ${GNUPGHOME}/dirmngr.conf
    # GPG key download sometimes fails for some reason and retrying fixes it.
    local retry_count=0
    local gpg_ok="false"
    set +e
    until [ "${gpg_ok}" = "true" ] || [ "${retry_count}" -eq "5" ];
    do
        echo "(*) Downloading GPG key..."
        ( echo "${keys}" | xargs -n 1 gpg -q ${keyring_args} --recv-keys) 2>&1 && gpg_ok="true"
        if [ "${gpg_ok}" != "true" ]; then
            echo "(*) Failed getting key, retrying in 10s..."
            (( retry_count++ ))
            sleep 10s
        fi
    done
    set -e
    if [ "${gpg_ok}" = "false" ]; then
        echo "(!) Failed to get gpg key."
        exit 1
    fi
}
# RHEL7/CentOS7 has an older gpg that does not have dirmngr
# Iterate through keyservers until we have all the keys downloaded
receive_gpg_keys_centos7() {
    local keys=${!1}
    local keyring_args=""
    local gpg_cmd="gpg"
    if [ ! -z "$2" ]; then
        mkdir -p "$(dirname \"$2\")"
        keyring_args="--no-default-keyring --keyring $2"
    fi
    if [ ! -z "${KEYSERVER_PROXY}" ]; then
        keyring_args="${keyring_args} --keyserver-options http-proxy=${KEYSERVER_PROXY}"
    fi

    # Install curl
    if ! type curl > /dev/null 2>&1; then
        check_packages curl
    fi

    # Use a temporary location for gpg keys to avoid polluting image
    export GNUPGHOME="/tmp/tmp-gnupg"
    mkdir -p ${GNUPGHOME}
    chmod 700 ${GNUPGHOME}
    # GPG key download sometimes fails for some reason and retrying fixes it.
    local retry_count=0
    local gpg_ok="false"
    num_keys=$(echo ${keys} | wc -w)
    set +e
        echo "(*) Downloading GPG keys..."
        until [ "${gpg_ok}" = "true" ] || [ "${retry_count}" -eq "5" ]; do
            for keyserver in $(echo "$(get_gpg_key_servers)" | sed 's/keyserver //'); do
                ( echo "${keys}" | xargs -n 1 gpg -q ${keyring_args} --recv-keys --keyserver=${keyserver} ) 2>&1
                downloaded_keys=$(gpg --list-keys | grep ^pub | wc -l)
                if [[ ${num_keys} = ${downloaded_keys} ]]; then
                    gpg_ok="true"
                    break
                fi
            done
            if [ "${gpg_ok}" != "true" ]; then
                echo "(*) Failed getting key, retrying in 10s..."
                (( retry_count++ ))
                sleep 10s
            fi
        done
    set -e
    if [ "${gpg_ok}" = "false" ]; then
        echo "(!) Failed to get gpg key."
        exit 1
    fi
}

find_version_from_git_tags() {
    local variable_name=$1
    local requested_version=${!variable_name}
    if [ "${requested_version}" = "none" ]; then return; fi
    local repository=$2
    local prefix=${3:-"tags/v"}
    local separator=${4:-"."}
    local last_part_optional=${5:-"false"}
    if [ "$(echo "${requested_version}" | grep -o "." | wc -l)" != "2" ]; then
        local escaped_separator=${separator//./\\.}
        local last_part
        if [ "${last_part_optional}" = "true" ]; then
            last_part="(${escaped_separator}[0-9]+)?"
        else
            last_part="${escaped_separator}[0-9]+"
        fi
        local regex="${prefix}\\K[0-9]+${escaped_separator}[0-9]+${last_part}$"
        local version_list="$(git ls-remote --tags ${repository} | grep -oP "${regex}" | tr -d ' ' | tr "${separator}" "." | sort -rV)"
        if [ "${requested_version}" = "latest" ] || [ "${requested_version}" = "current" ] || [ "${requested_version}" = "lts" ]; then
            declare -g ${variable_name}="$(echo "${version_list}" | head -n 1)"
        else
            set +e
            declare -g ${variable_name}="$(echo "${version_list}" | grep -E -m 1 "^${requested_version//./\\.}([\\.\\s]|$)")"
            set -e
        fi
    fi
    if [ -z "${!variable_name}" ] || ! echo "${version_list}" | grep "^${!variable_name//./\\.}$" > /dev/null 2>&1; then
        echo -e "Invalid ${variable_name} value: ${requested_version}\nValid values:\n${version_list}" >&2
        exit 1
    fi
    echo "${variable_name}=${!variable_name}"
}

# Use semver logic to decrement a version number then look for the closest match
find_prev_version_from_git_tags() {
    local variable_name=$1
    local current_version=${!variable_name}
    local repository=$2
    # Normally a "v" is used before the version number, but support alternate cases
    local prefix=${3:-"tags/v"}
    # Some repositories use "_" instead of "." for version number part separation, support that
    local separator=${4:-"."}
    # Some tools release versions that omit the last digit (e.g. go)
    local last_part_optional=${5:-"false"}
    # Some repositories may have tags that include a suffix (e.g. actions/node-versions)
    local version_suffix_regex=$6
    # Try one break fix version number less if we get a failure. Use "set +e" since "set -e" can cause failures in valid scenarios.
    set +e
        major="$(echo "${current_version}" | grep -oE '^[0-9]+' || echo '')"
        minor="$(echo "${current_version}" | grep -oP '^[0-9]+\.\K[0-9]+' || echo '')"
        breakfix="$(echo "${current_version}" | grep -oP '^[0-9]+\.[0-9]+\.\K[0-9]+' 2>/dev/null || echo '')"

        if [ "${minor}" = "0" ] && [ "${breakfix}" = "0" ]; then
            ((major=major-1))
            declare -g ${variable_name}="${major}"
            # Look for latest version from previous major release
            find_version_from_git_tags "${variable_name}" "${repository}" "${prefix}" "${separator}" "${last_part_optional}"
        # Handle situations like Go's odd version pattern where "0" releases omit the last part
        elif [ "${breakfix}" = "" ] || [ "${breakfix}" = "0" ]; then
            ((minor=minor-1))
            declare -g ${variable_name}="${major}.${minor}"
            # Look for latest version from previous minor release
            find_version_from_git_tags "${variable_name}" "${repository}" "${prefix}" "${separator}" "${last_part_optional}"
        else
            ((breakfix=breakfix-1))
            if [ "${breakfix}" = "0" ] && [ "${last_part_optional}" = "true" ]; then
                declare -g ${variable_name}="${major}.${minor}"
            else
                declare -g ${variable_name}="${major}.${minor}.${breakfix}"
            fi
        fi
    set -e
}

install_openssl3() {
    mkdir /tmp/openssl3
    (
        cd /tmp/openssl3
        openssl3_version="3.0"
        # Find version using soft match
        find_version_from_git_tags openssl3_version "https://github.com/openssl/openssl" "openssl-"
        local tgz_filename="openssl-${openssl3_version}.tar.gz"
        local tgz_url="https://github.com/openssl/openssl/releases/download/openssl-${openssl3_version}/${tgz_filename}"
        echo "Downloading ${tgz_filename}..."
        curl -sSL -o "/tmp/openssl3/${tgz_filename}" "${tgz_url}"
        tar xzf ${tgz_filename}
        cd openssl-${openssl3_version}
        ./config --libdir=lib
        make -j $(nproc)
        make install_dev
    )
    rm -rf /tmp/openssl3
}

install_prev_vers_cpython() {
    VERSION=$1
    echo -e "\n(!) Failed to fetch the latest artifacts for cpython ${VERSION}..."
    find_prev_version_from_git_tags VERSION https://github.com/python/cpython
    echo -e "\nAttempting to install ${VERSION}"
    install_cpython "${VERSION}"
}

install_cpython() {
    VERSION=$1
    INSTALL_PATH="${PYTHON_INSTALL_PATH}/${VERSION}"

    # Check if the specified Python version is already installed
    if [ -d "${INSTALL_PATH}" ]; then
        echo "(!) Python version ${VERSION} already exists."
    else
        mkdir -p /tmp/python-src ${INSTALL_PATH}
        cd /tmp/python-src
        cpython_tgz_filename="Python-${VERSION}.tgz"
        cpython_tgz_url="https://www.python.org/ftp/python/${VERSION}/${cpython_tgz_filename}"
        echo "Downloading ${cpython_tgz_filename}..."
        curl -sSL -o "/tmp/python-src/${cpython_tgz_filename}" "${cpython_tgz_url}"
    fi
}

install_from_source() {
    VERSION=$1
    echo "(*) Building Python ${VERSION} from source..."
    if ! type git > /dev/null 2>&1; then
        check_packages git
    fi

    # Find version using soft match
    find_version_from_git_tags VERSION "https://github.com/python/cpython"

    # Some platforms/os versions need modern versions of openssl installed
    # via common package repositories, for now rhel-7 family, use case statement to
    # make it easy to expand
    SSL_INSTALL_PATH="/usr/local"
    case ${VERSION_CODENAME} in
        centos7|rhel7)
            check_packages perl-IPC-Cmd
            install_openssl3
            ADDL_CONFIG_ARGS="--with-openssl=${SSL_INSTALL_PATH} --with-openssl-rpath=${SSL_INSTALL_PATH}/lib"
            ;;
    esac

    install_cpython "${VERSION}"
    if [ -f "/tmp/python-src/${cpython_tgz_filename}" ]; then
        if grep -q "404 Not Found" "/tmp/python-src/${cpython_tgz_filename}"; then
            install_prev_vers_cpython "${VERSION}"
        fi
    fi;
    # Verify signature
    if [[ ${VERSION_CODENAME} = "centos7" ]] || [[ ${VERSION_CODENAME} = "rhel7" ]]; then
        receive_gpg_keys_centos7 PYTHON_SOURCE_GPG_KEYS
    else
        receive_gpg_keys PYTHON_SOURCE_GPG_KEYS
    fi
    echo "Downloading ${cpython_tgz_filename}.asc..."
    curl -sSL -o "/tmp/python-src/${cpython_tgz_filename}.asc" "${cpython_tgz_url}.asc"
    gpg --verify "${cpython_tgz_filename}.asc"

    # Update min protocol for testing only - https://bugs.python.org/issue41561
    if [ -f /etc/pki/tls/openssl.cnf ]; then
        cp /etc/pki/tls/openssl.cnf /tmp/python-src/
    else
        cp /etc/ssl/openssl.cnf /tmp/python-src/
    fi
    sed -i -E 's/MinProtocol[=\ ]+.*/MinProtocol = TLSv1.0/g' /tmp/python-src/openssl.cnf
    export OPENSSL_CONF=/tmp/python-src/openssl.cnf

    # Untar and build
    tar -xzf "/tmp/python-src/${cpython_tgz_filename}" -C "/tmp/python-src" --strip-components=1
    local config_args=""
    if [ "${OPTIMIZE_PYTHON_BUILD_FROM_SOURCE}" = "true" ]; then
        config_args="${config_args} --enable-optimizations"
    fi
    if [ "${ENABLESHARED}" = "true" ]; then
        config_args=" ${config_args} --enable-shared"
        # need double-$: LDFLAGS ends up in Makefile $$ becomes $ when evaluated.
        # backslash needed for shell that Make calls escape the $.
        export LDFLAGS="${LDFLAGS} -Wl,-rpath="'\$$ORIGIN'"/../lib"
    fi
    if [ -n "${ADDL_CONFIG_ARGS}" ]; then
        config_args="${config_args} ${ADDL_CONFIG_ARGS}"
    fi
    ./configure --prefix="${INSTALL_PATH}" --with-ensurepip=install ${config_args}
    make -j 8
    make install

    cd /tmp
    rm -rf /tmp/python-src ${GNUPGHOME} /tmp/vscdc-settings.env

    ln -s "${INSTALL_PATH}/bin/python3" "${INSTALL_PATH}/bin/python"
    ln -s "${INSTALL_PATH}/bin/pip3" "${INSTALL_PATH}/bin/pip"
    ln -s "${INSTALL_PATH}/bin/idle3" "${INSTALL_PATH}/bin/idle"
    ln -s "${INSTALL_PATH}/bin/pydoc3" "${INSTALL_PATH}/bin/pydoc"
    ln -s "${INSTALL_PATH}/bin/python3-config" "${INSTALL_PATH}/bin/python-config"

    add_symlink

}

install_devel_packages() {
    
    # General requirements
    REQUIRED_PKGS=""
    case ${ADJUSTED_ID} in
        debian)
            REQUIRED_PKGS="${REQUIRED_PKGS} \
                ca-certificates \
                curl \
                dirmngr \
                gcc \
                gnupg2 \
                libbz2-dev \
                libffi-dev \
                libgdbm-dev \
                liblzma-dev \
                libncurses5-dev \
                libreadline-dev \
                libsqlite3-dev \
                libssl-dev \
                libxml2-dev \
                libxmlsec1-dev \
                make \
                tar \
                tk-dev \
                uuid-dev \
                xz-utils \
                zlib1g-dev"
            ;;
        rhel)
            REQUIRED_PKGS="${REQUIRED_PKGS} \
                bzip2-devel \
                ca-certificates \
                findutils \
                gcc \
                gnupg2 \
                libffi-devel \
                libxml2-devel \
                make \
                ncurses-devel \
                openssl-devel \
                shadow-utils \
                sqlite-devel \
                tar \
                which \
                xz-devel \
                xz \
                zlib-devel"
            if ! type curl >/dev/null 2>&1; then
                REQUIRED_PKGS="${REQUIRED_PKGS} \
                    curl"
            fi
            # Mariner does not have tk-devel package available, RedHat ubi8 and ubi9 do not have tk-devel
            if [ ${ID} != "mariner" ] && [ ${ID} != "rhel" ]; then
                REQUIRED_PKGS="${REQUIRED_PKGS} \
                    tk-devel"
            fi
            # Redhat ubi8 and ubi9 do not have some packages by default, only add them
            # if we're not on RedHat ...
            if [ ${ID} != "rhel" ]; then
                REQUIRED_PKGS="${REQUIRED_PKGS} \
                    gdbm-devel \
                    readline-devel \
                    uuid-devel \
                    xmlsec1-devel"
            fi
            ;;
    esac

    check_packages ${REQUIRED_PKGS}
}

install_python() {
    version=$1
    CURRENT_PATH="${PYTHON_INSTALL_PATH}/current"

    if ! cat /etc/group | grep -e "^python:" > /dev/null 2>&1; then
        groupadd -r python
    fi

    usermod -a -G python "${USERNAME}"

    # If the os-provided versions are "good enough", detect that and bail out.
    if [ ${version} = "os-provided" ] || [ ${version} = "system" ]; then
        if [ ${ADJUSTED_ID} = "debian" ]; then
            check_packages python3 python3-doc python3-pip python3-venv python3-dev python3-tk
        else
            if [ ${ID} != "mariner" ]; then
                check_packages python3 python3-pip python3-devel python3-tkinter
            else
                check_packages python3 python3-pip python3-devel
            fi
        fi
        INSTALL_PATH="/usr"

        local current_bin_path="${CURRENT_PATH}/bin"
        if [ "${OVERRIDE_DEFAULT_VERSION}" = "true" ]; then
            rm -rf "${current_bin_path}"
        fi
        if [ ! -d "${current_bin_path}" ] ; then
            mkdir -p "${current_bin_path}"
            # Add an interpreter symlink but point it to "/usr" since python is at /usr/bin/python, add other alises
            ln -s "${INSTALL_PATH}/bin/python3" "${current_bin_path}/python3"
            ln -s "${INSTALL_PATH}/bin/python3" "${current_bin_path}/python"
            ln -s "${INSTALL_PATH}/bin/pydoc3" "${current_bin_path}/pydoc3"
            ln -s "${INSTALL_PATH}/bin/pydoc3" "${current_bin_path}/pydoc"
            ln -s "${INSTALL_PATH}/bin/python3-config" "${current_bin_path}/python3-config"
            ln -s "${INSTALL_PATH}/bin/python3-config" "${current_bin_path}/python-config"
        fi

        should_install_from_source=false
    fi

    install_devel_packages

    if [ ${ADJUSTED_ID} = "debian" ] && [ "$(dpkg --print-architecture)" = "amd64" ] && [ "${USE_ORYX_IF_AVAILABLE}" = "true" ] && type oryx > /dev/null 2>&1; then
        install_using_oryx $version || should_install_from_source=true
    else
        should_install_from_source=true
    fi
    if [ "${should_install_from_source}" = "true" ]; then
        install_from_source $version
    fi

    if [ ${version} != "os-provided" ] && [ ${version} != "system" ]; then
        updaterc "if [[ \"\${PATH}\" != *\"${CURRENT_PATH}/bin\"* ]]; then export PATH=${CURRENT_PATH}/bin:\${PATH}; fi"
        PATH="${INSTALL_PATH}/bin:${PATH}"
    fi

    # Updates the symlinks for os-provided, or the installed python version in other cases
    chown -R "${USERNAME}:python" "${PYTHON_INSTALL_PATH}"
    chmod -R g+r+w "${PYTHON_INSTALL_PATH}"
    find "${PYTHON_INSTALL_PATH}" -type d -print0 | xargs -0 -n 1 chmod g+s

    PYTHON_SRC="${INSTALL_PATH}/bin/python3"
    if ! type pip >/dev/null 2>&1 && type pip3 >/dev/null 2>&1; then
        ln -s /usr/bin/pip3 /usr/bin/pip
    fi
}

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo -e 'Script must be run as root. Use sudo, su, or add "USER root" to your Dockerfile before running this script.'
    exit 1
fi

# Bring in ID, ID_LIKE, VERSION_ID, VERSION_CODENAME
. /etc/os-release
# Get an adjusted ID independent of distro variants
MAJOR_VERSION_ID=$(echo ${VERSION_ID} | cut -d . -f 1)
if [ "${ID}" = "debian" ] || [ "${ID_LIKE}" = "debian" ]; then
    ADJUSTED_ID="debian"
elif [[ "${ID}" = "rhel" || "${ID}" = "fedora" || "${ID}" = "mariner" || "${ID_LIKE}" = *"rhel"* || "${ID_LIKE}" = *"fedora"* || "${ID_LIKE}" = *"mariner"* ]]; then
    ADJUSTED_ID="rhel"
    if [[ "${ID}" = "rhel" ]] || [[ "${ID}" = *"alma"* ]] || [[ "${ID}" = *"rocky"* ]]; then
        VERSION_CODENAME="rhel${MAJOR_VERSION_ID}"
    else
        VERSION_CODENAME="${ID}${MAJOR_VERSION_ID}"
    fi
else
    echo "Linux distro ${ID} not supported."
    exit 1
fi

if [ "${ADJUSTED_ID}" = "rhel" ] && [ "${VERSION_CODENAME-}" = "centos7" ]; then
    # As of 1 July 2024, mirrorlist.centos.org no longer exists.
    # Update the repo files to reference vault.centos.org.
    sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo
    sed -i s/^#.*baseurl=http/baseurl=http/g /etc/yum.repos.d/*.repo
    sed -i s/^mirrorlist=http/#mirrorlist=http/g /etc/yum.repos.d/*.repo
fi

# To find some devel packages, some rhel need to enable specific extra repos, but not on RedHat ubi images...
INSTALL_CMD_ADDL_REPO=""
if [ ${ADJUSTED_ID} = "rhel" ] && [ ${ID} != "rhel" ]; then
    if [ ${MAJOR_VERSION_ID} = "8" ]; then
        INSTALL_CMD_ADDL_REPOS="--enablerepo powertools"
    elif [ ${MAJOR_VERSION_ID} = "9" ]; then
        INSTALL_CMD_ADDL_REPOS="--enablerepo crb"
    fi
fi

# Setup INSTALL_CMD & PKG_MGR_CMD
if type apt-get > /dev/null 2>&1; then
    PKG_MGR_CMD=apt-get
    INSTALL_CMD="${PKG_MGR_CMD} -y install --no-install-recommends"
elif type microdnf > /dev/null 2>&1; then
    PKG_MGR_CMD=microdnf
    INSTALL_CMD="${PKG_MGR_CMD} ${INSTALL_CMD_ADDL_REPOS} -y install --refresh --best --nodocs --noplugins --setopt=install_weak_deps=0"
elif type dnf > /dev/null 2>&1; then
    PKG_MGR_CMD=dnf
    INSTALL_CMD="${PKG_MGR_CMD} ${INSTALL_CMD_ADDL_REPOS} -y install --refresh --best --nodocs --noplugins --setopt=install_weak_deps=0"
else
    PKG_MGR_CMD=yum
    INSTALL_CMD="${PKG_MGR_CMD} ${INSTALL_CMD_ADDL_REPOS} -y install --noplugins --setopt=install_weak_deps=0"
fi

# Clean up
clean_up() {
    case ${ADJUSTED_ID} in
        debian)
            rm -rf /var/lib/apt/lists/*
            ;;
        rhel)
            rm -rf /var/cache/dnf/* /var/cache/yum/*
            rm -rf /tmp/yum.log
            rm -rf ${GPG_INSTALL_PATH}
            ;;
    esac
}
clean_up

updaterc() {
    local _bashrc
    local _zshrc
    if [ "${UPDATE_RC}" = "true" ]; then
        case $ADJUSTED_ID in
            debian) echo "Updating /etc/bash.bashrc and /etc/zsh/zshrc..."
                _bashrc=/etc/bash.bashrc
                _zshrc=/etc/zsh/zshrc
                ;;
            rhel) echo "Updating /etc/bashrc and /etc/zshrc..."
                _bashrc=/etc/bashrc
                _zshrc=/etc/zshrc
            ;;
        esac
        if [[ "$(cat ${_bashrc})" != *"$1"* ]]; then
            echo -e "$1" >> ${_bashrc}
        fi
        if [ -f "${_zshrc}" ] && [[ "$(cat ${_zshrc})" != *"$1"* ]]; then
            echo -e "$1" >> ${_zshrc}
        fi
    fi
}

python_is_externally_managed() {
    local _python_cmd=$1
    local python_stdlib_dir=$(
        ${_python_cmd} -c '
import sys
import sysconfig
sys.prefix == sys.base_prefix and print(sysconfig.get_path("stdlib", sysconfig.get_default_scheme()))'
    )
    if [ -f ${python_stdlib_dir}/EXTERNALLY-MANAGED ]; then
        return 0
    else
        return 1
    fi
}

install_pipx_package() {

    local package="$1"
    local package_version="$2"

    echo 'Check if pipx is installed'

    if ! type pipx > /dev/null 2>&1; then
        echo 'Installing pix...'
        check_packages pipx
    else
        echo 'pipx already installed'
    fi

    sudo -i -u ${USERNAME} bash -c "pipx install ${package}==${package_version:-==latest}"
}

# Ensure that login shells get the correct path if the user updated the PATH using ENV.
rm -f /etc/profile.d/00-restore-env.sh
echo "export PATH=${PATH//$(sh -lc 'echo $PATH')/\$PATH}" > /etc/profile.d/00-restore-env.sh
chmod +x /etc/profile.d/00-restore-env.sh

# Some distributions do not install awk by default (e.g. Mariner)
if ! type awk >/dev/null 2>&1; then
    check_packages awk
fi

# Determine the appropriate non-root user
if [ "${USERNAME}" = "auto" ] || [ "${USERNAME}" = "automatic" ]; then
    USERNAME=""
    POSSIBLE_USERS=("vscode" "node" "codespace" "$(awk -v val=1000 -F ":" '$3==val{print $1}' /etc/passwd)")
    for CURRENT_USER in "${POSSIBLE_USERS[@]}"; do
        if id -u ${CURRENT_USER} > /dev/null 2>&1; then
            USERNAME=${CURRENT_USER}
            break
        fi
    done
    if [ "${USERNAME}" = "" ]; then
        USERNAME=root
    fi
elif [ "${USERNAME}" = "none" ] || ! id -u ${USERNAME} > /dev/null 2>&1; then
    USERNAME=root
fi

# Ensure apt is in non-interactive to avoid prompts
export DEBIAN_FRONTEND=noninteractive

if PYTHON_FINDER_RESULT=$(version_finder python); then

    read PYTHON_CMD PYTHON_VERSION <<< "${PYTHON_FINDER_RESULT//$'\t'/ }"
    echo "Found $PYTHON_CMD version $PYTHON_VERSION"

    if python_is_externally_managed ${PYTHON_CMD}; then

        echo "Python is externally managed"

        find_version_from_git_tags PRE_COMMIT_VERSION "https://github.com/pre-commit/pre-commit"

        install_with_pipx pre-commit ${PRE_COMMIT_VERSION}

    else

        echo "Python is not externally managed"

    fi

else
    echo "Python not found, installing latest..."

    install_python latest

fi

# Clean up
clean_up

echo "Done!"
