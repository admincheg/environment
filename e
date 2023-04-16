#!/bin/bash

# {{{ Defines
declare _COLOR='\[\e[38;5;215m\]'
declare _NOCOLOR='\[\e[0m\]'
declare _PREFIX="${HOME}/.config/env"
declare _CACHE_DIR="/run/user/${UID}/env-cache"
declare _CONFIG_DIR="${HOME}/.config/env"

declare _USED_ENVIRONMENT=(
	"VAULT_ADDR"
	"VAULT_TOKEN"
	"NOMAD_ADDR"
	"NOMAD_TOKEN"
	"AWS_PROFILE"
	"AWS_ACCESS_KEY_ID"
	"AWS_SECRET_ACCESS_KEY"
	"AWS_SESSION_TOKEN"
	"AWS_DEFAULT_REGION"
	"ENV_AWS_AUTH_TYPE"
)
# }}}

# {{{ Preflight checks
if [[ ! -d "${_PREFIX}" ]]; then
	mkdir -p ${_PREFIX}
fi

if [[ -f "${HOME}/.local/share/owllib/helpers.sh" ]]; then
	. "${HOME}/.local/share/owllib/helpers.sh"
else
	echo "[!!!] OwlLib helper is not found"
	exit 1
fi
# }}}

# {{{ Functions
# {{{ Helpers
# {{{ _disable_all(hash_ref config)
_disable_all() {
	declare -n _config="$1"; shift

	for i in ${!_config[@]}; do
		_config[$i]=0
	done
}
# }}}
# }}}

# {{{ Checks
# {{{ _check_vault_token(string addr, string token)
_check_vault_token() {
	declare -x VAULT_ADDR="$1"; shift
	declare -x VAULT_TOKEN="$1"; shift

	if [[ -z "${VAULT_ADDR}" ]]; then
		_warn "Vault address is not defined"
		return 1
	fi

	if [[ -z "${VAULT_TOKEN}" ]]; then
		_debug "Vault token is not specified, nothing to check"
		return 1
	fi

	declare _err=""
	_err=$(vault token lookup 2>&1)
	if [[ $? -gt 0 ]]; then
		_warn "Specified token is not working"
		_debug "${_err}"
		return 1
	fi
}
# }}}

# {{{ _check_nomad_token(string addr, string token)
_check_nomad_token() {
	declare -x NOMAD_ADDR="$1"; shift
	declare -x NOMAD_TOKEN="$1"; shift

	if [[ -z "${NOMAD_ADDR}" ]]; then
		_warn "Nomad address is not defined"
		return 1
	fi

	if [[ -z "${NOMAD_TOKEN}" ]]; then
		_debug "Nomad token is not specified, nothing to check"
		return 1
	fi

	nomad status > /dev/null

	if [[ $? -gt 0 ]]; then
		_debug "Specified token is not working"
		return 1
	fi
}
# }}}

# {{{ _check_aws_creds(string type, string access_key, string secret_key, string session_token)
_check_aws_creds() {
	declare _type="$1"; shift
	declare _access="$1"; shift
	declare _secret="$1"; shift
	declare _session="$1"; shift

	_debug "Define AWS variables"
	case "${_type}" in
		profile)
			declare -x AWS_PROFILE="${_access}"
			;;
		token|vault)
			declare -x AWS_ACCESS_KEY_ID="${_access}"
			declare -x AWS_SECRET_ACCESS_KEY="${_secret}"

			if [[ -n "${_session}" ]]; then
				declare -x AWS_SESSION_TOKEN="${_session}"
			fi
			;;
		*)
			_warn "Auth type ${_type} is not implemented yet"
			return 1
			;;
	esac

	declare _wait=0
	if [[ "${_type}" == "vault" ]]; then
		# Vault AWS creds provisioning little bit laggy, add some delay (12 times by 5 seconds)
		while :; do
			if [[ ${_wait} -eq 12 ]]; then
				_warn "Vault returns failed creds for AWS"
				return 1
			fi
			_debug "Waiting for AWS creds propagation"
			aws sts get-caller-identity &> /dev/null

			if [[ $? -eq 0 ]]; then
				break
			fi

			_wait=$((_wait + 1))
			sleep 5
		done
	fi

	_ret=$(aws sts get-caller-identity 2>&1 | grep -v '^$')
	if [[ $? -gt 0 ]]; then
		_debug "AWS auth by ${_type} failed"
		_warn "${_ret}"
		return 1
	fi
}
# }}}
# }}}

# {{{ Auth
# {{{ _aws_auth(hash_ref result_config, hash_ref config)
_aws_auth() {
	declare -n _ret_config="$1"; shift
	declare -n _config_aws_creds="$1"; shift
	declare -i _err=0
	declare _access _secret _session

	_debug "Start AWS credentials obtainig"

	case "${_config_aws_creds[type]}" in
		profile)
			if [[ -z "${_config_aws_creds[access_key]}" ]]; then
				_warn "AWS profile name is not defined"
				return 1
			fi
			_access="${_config_aws_creds[access_key]}"
			;;
		token)
			if [[ -z "${_config_aws_creds[access_key]}" || -z "${_config_aws_creds[secret_key]}" ]]; then
				_warn "AWS access key or secret key is not defined"
				return 1
			fi
			_access="${_config_aws_creds[access_key]}"
			_secret="${_config_aws_creds[secret_key]}"
			_session="${_config_aws_creds[session_token]}"
			;;
		vault)
			if [[ -z "${VAULT_ADDR}" || -z "${VAULT_TOKEN}" ]]; then
				_warn "Variables VAULT_ADDR or VAULT_TOKEN is not defined"
				return 1
			fi
			read _access _secret _session < <(vault read -format=json "${_config_aws_creds[access_key]}/creds/${_config_aws_creds[secret_key]}" | jq -r '.data | [.access_key,.secret_key,.security_token] | @tsv')
			;;
		*)
			_warn "Auth type ${_config_aws_creds[type]} is not implemented yet"
			return 1
			;;
	esac

	_check_aws_creds "${_config_aws_creds[type]}" "${_access}" "${_secret}" "${_session}"
	_err=$?
	if [[ ${_err} -eq 0 ]]; then
		_ret_config[type]="${_config_aws_creds[type]}"
		_ret_config[access_key]="${_access}"
		_ret_config[secret_key]="${_secret}"
		_ret_config[session_token]="${_session}"
	fi
}
# }}}

# {{{ _vault_auth(string_ref token, hash_ref config)
_vault_auth() {
	declare -n _token="$1"; shift
	declare -n _config_vault="$1"; shift
	declare -i _err=0
	declare _temp_token=""
	declare _additional_args=""

	_debug "Start Vault credentials obtaining"

	if [[ -z "${_config_vault[server]}" ]]; then
		_debug "Vault address is not specified"
		return 1
	fi

	if [[ -z "${_config_vault[type]}" || -z "${_config_vault[role]}" ]]; then
		_debug "Type or role is not specified, we can not login"
		return 1
	fi

	if [[ -z "${_config_vault[secret]}" ]]; then
		_warn "Secret is not defined. Try to obtain interactive"
	fi

	declare -x VAULT_ADDR="${_config_vault[server]}"
	case "${_config_vault[type]}" in
		userpass|ldap)
			if [[ -n "${_config_vault[secret]}" ]]; then
				_additional_args="password=${_config_vault[secret]}"
			fi

			vault login -field token -method=${_config_vault[type]} username="${_config_vault[role]}" ${_additional_args} > /tmp/token
			_err=$?
			if [[ ${_err} -eq 0 ]]; then
				_temp_token=$(< /tmp/token)
			else
				return 1
			fi
			;;
		oidc)
			vault login -field token -method=${_config_vault[type]} role="${_config_vault[role]}" > /tmp/token
			_err=$?
			if [[ ${_err} -eq 0 ]]; then
				_temp_token=$(< /tmp/token)
			else
				return 1
			fi
			;;
		*)
			_debug "Auth type ${_type} is not implemented"
			return 1
			;;
	esac

	_check_vault_token "${_config_vault[server]}" "${_temp_token}"
	_err=$?

	if [[ ${_err} -eq 0 ]]; then
		_token=${_temp_token}
	fi

	return ${_err}
}
# }}}

# {{{ _nomad_auth(string_ref token, hash_ref config)
_nomad_auth() {
	declare -n _token="$1"; shift
	declare -n _config_nomad_creds="$1"; shift
	declare -i _err=0

	_debug "Start Nomad credentials obtainig"

	if [[ -z "${_config_nomad_creds[server]}" ]]; then
		_warn "Nomad server url is not defined"
		return 1
	fi

	case "${_config_nomad_creds[type]}" in
		vault)
			if [[ -z "${VAULT_ADDR}" || -z "${VAULT_TOKEN}" ]]; then
				_warn "Variables VAULT_ADDR or VAULT_TOKEN is not defined"
				return 1
			fi
			_token=$(vault read -field=secret_id "${_config_nomad_creds[secret]}/creds/${_config_nomad_creds[role]}" 2>&1)
			if [[ $? -gt 0 || -z "${_token}" ]]; then
				_warn "Failed to obtain Nomad token"
				_debug "${_token}"
				_token=""
				return 1
			fi
			;;
		*)
			_warn "Auth type ${_config_aws_creds[type]} is not implemented yet"
			return 1
			;;
	esac

	_check_nomad_token "${_config_nomad_creds[server]}" "${_token}"
	return $?
}
# }}}
# }}}

# {{{ Cache
# {{{ _cache_path(string_ref cache_path, string prefix, string creds_type)
_cache_path() {
	declare -n _cache_path="$1"; shift
	declare _prefix="$1"; shift
	declare _creds_type="$1"; shift

	_cache_path="${_CACHE_DIR}/${_prefix}.${_creds_type}"
}
# }}}

# {{{ _cache_global(string prefix, string creds_path)
_cache_global() {
	declare _prefix="$1"; shift
	declare _creds_path="$1"; shift

	_debug "Add cached credentials to global cache for ${_prefix} environment"
	declare _global_cache=""
	_cache_path _global_cache "${_prefix}" "env"
	echo ". ${_creds_path}" >> "${_global_cache}"

}
# }}}

# {{{ _check_cache(string prefix, string creds_type)
_check_cache() {
	declare _prefix="$1"; shift
	declare _creds_type="$1"; shift

	declare _creds_cache=""
	declare -i _err=0

	_debug "Start checking cached creds for ${_creds_type} in ${_prefix} env"

	_cache_path _creds_cache "${_prefix}" "${_creds_type}"
	if [[ ! -f "${_creds_cache}" ]]; then
		_debug "Cache for ${_creds_type} in ${_prefix} is not found"
		_debug "File ${_creds_cache} is not found"
		return 1
	fi

	if [[ "${_creds_type}" != "banner" ]]; then
		. "${_creds_cache}"
	fi

	case "${_creds_type}" in
		vault)
			_check_vault_token "${VAULT_ADDR}" "${VAULT_TOKEN}"
			_err=$?
			;;
		aws)
			case "${ENV_AWS_AUTH_TYPE}" in
				profile)
					_check_aws_creds "${ENV_AWS_AUTH_TYPE}" "${AWS_PROFILE}"
					_err=$?
					;;
				vault|token)
					_check_aws_creds "${ENV_AWS_AUTH_TYPE}" "${AWS_ACCESS_KEY_ID}" "${AWS_SECRET_ACCESS_KEY}" "${AWS_SESSION_TOKEN}"
					_err=$?
					;;
			esac
			;;
		nomad)
			_check_nomad_token "${NOMAD_ADDR}" "${NOMAD_TOKEN}"
			_err=$?
			;;
		prompt|banner)
			_err=0
			;;
		*)
			_warn "Cache for ${_creds_type} is not implemented"
			return 1
			;;
	esac

	if [[ ${_err} -gt 0 ]]; then
		_warn "Cached credentials for ${_creds_type} failed"
		rm -f "${_creds_cache}"
		return 1
	else
		_cache_global "${_prefix}" "${_creds_cache}"
	fi
}
# }}}

# {{{ _cache_creds(array_ref data, string prefix, string creds_type)
_cache_creds() {
	declare -n _data="$1"; shift
	declare _prefix="$1"; shift
	declare _creds_type="$1"; shift

	_debug "Start caching creds for ${_creds_type}"

	if [[ ! -d "${_CACHE_DIR}" ]]; then
		_debug "Create cache directory ${_CACHE_DIR}"
		declare _ret=$(mkdir "${_CACHE_DIR}" 2>&1)
		if [[ $? -gt 0 ]]; then
			_warn "Failed to create cache directory"
			_debug "${_ret}"
			return 1
		fi
	fi

	declare _creds_cache=""
	_cache_path _creds_cache "${_prefix}" "${_creds_type}"

	case "${_creds_type}" in
		vault|aws|nomad|prompt|banner|custom_env)
			if [[ -f "${_creds_cache}" ]]; then
				rm -f "${_creds_cache}"
			fi

			for i in "${_data[@]}"; do
				cat >> "${_creds_cache}" <<-EOF
				${i}
EOF
			done
			;;
		env)
			_debug "Cleanup environment cache for ${_prefix}"
			rm -f "${_creds_cache}"
			return 0
			;;
		*)
			_warn "Caching for ${_creds_type} is not implemented"
			return 1
			;;
	esac

	_debug "Credentials for ${_creds_type} in ${_prefix} env placed to ${_creds_cache}"
	_cache_global "${_prefix}" "${_creds_cache}"
}
# }}}

# {{{ _cache_clear(string prefix)
_cache_clear() {
	declare _prefix="$1"; shift

	declare _cache_env=""
	_cache_path _cache_env "${_prefix}" "env"
	_cache_env="${_cache_env%.*}.*"

	_debug "Clear cache at '${_cache_env}'"
	rm -f ${_cache_env}
	_info "Cache for '${_prefix}' cleared"
}
# }}}
# }}}

# {{{ Credentials providers
# {{{ _obtain_credentials_vault(hash_ref config, string env, int enabled)
_obtain_credentials_vault() {
	declare -n _config="$1"; shift
	declare _env="$1"; shift
	declare -i _enabled="$1"; shift

	declare -a _vault_cache=()

	if [[ ${_enabled} -eq 1 ]]; then
		_debug "Auth in vault"
		if [[ -z "${!_config[@]}" ]]; then
			_warn "Vault configuration is not defined"
			return 1
		fi

		_check_cache "${_env}" "vault"
		if [[ $? -gt 0 ]]; then
			declare _vault_token=""

			_vault_auth _vault_token _config_module_vault
			if [[ $? -gt 0 ]]; then
				_warn "Failed to obtain Vault credentials"
				return 1
			fi

			_debug "Vault token successfully obtained"
			_vault_cache=(
				"declare -x VAULT_ADDR='${_config[server]}'"
				"declare -x VAULT_TOKEN='${_vault_token}'"
			)
		else
			_debug "Cached credentials for Vault still alive"
		fi
	else
		_debug "Vault module disabled, unset environment"
		_vault_cache=(
			"unset VAULT_ADDR VAULT_TOKEN"
		)
	fi

	if [[ -n "${_vault_cache[@]}" ]]; then
		_cache_creds _vault_cache "${_env}" "vault"
	fi
}
# }}}

# {{{ _obtain_credentials_aws(hash_ref config, string env, int enabled)
_obtain_credentials_aws() {
	declare -n _config="$1"; shift
	declare _env="$1"; shift
	declare -i _enabled="$1"; shift

	declare -a _aws_cache=()

	if [[ ${_enabled} -eq 1 ]]; then
		_debug "AWS auth"

		if [[ -z "${!_config[@]}" ]]; then
			_warn "AWS configuration is not defined"
			return 1
		fi

		_check_cache "${_env}" "aws"
		if [[ $? -gt 0 ]]; then
			if [[ "${_config[type]}" == "vault" ]]; then
				declare _vault_cache=""
				_cache_path _vault_cache "${_env}" "vault"
				if [[ -n "${_vault_cache}" && -f "${_vault_cache}" ]]; then
					. "${_vault_cache}"
				else
					_warn "Vault credentials is not found"
				fi
			fi

			declare -A _aws_creds=()
			_aws_auth _aws_creds "${!_config}"
			if [[ $? -gt 0 ]]; then
				_warn "Failed to check AWS credentials"
				return 1
			else
				_debug "AWS creds successfully checked"
			fi

			case "${_config[type]}" in
				profile)
					_aws_cache=(
						"declare -x AWS_PROFILE='${_aws_creds[access_key]}'"
						"unset AWS_DEFAULT_REGION"
					)
					;;
				key|vault)
					_aws_cache=(
						"declare -x AWS_ACCESS_KEY_ID='${_aws_creds[access_key]}'"
						"declare -x AWS_SECRET_ACCESS_KEY='${_aws_creds[secret_key]}'"
					)
					if [[ -n "${_aws_creds[session_token]}" ]]; then
						_aws_cache=(
							"${_aws_cache[@]}"
							"declare -x AWS_SESSION_TOKEN='${_aws_creds[session_token]}'"
						)
					fi
			esac

			if [[ -n "${_config[region]}" ]]; then
				_aws_cache=(
					"${_aws_cache[@]}"
					"declare -x AWS_DEFAULT_REGION='${_config[region]}'"
				)
			fi

			if [[ -n "${_config[output]}" ]]; then
				_aws_cache=(
					"${_aws_cache[@]}"
					"declare -x AWS_DEFAULT_OUTPUT='${_config[output]}'"
				)
			fi

			_aws_cache=(
				"${_aws_cache[@]}"
				"declare -x ENV_AWS_AUTH_TYPE='${_config[type]}'"
			)

			_debug "AWS creds successfully obtained"
		else
			_debug "Cached credentials for AWS still alive"
		fi
	else
		_debug "AWS module disabled, unset environment"
		_aws_cache=(
			"unset AWS_PROFILE ENV_AWS_AUTH_TYPE AWS_ACCESS_KEY_ID AWS_ACCESS_SECRET_KEY AWS_SESSION_TOKEN"
		)
	fi

	if [[ -n "${_aws_cache[@]}" ]]; then
		_cache_creds _aws_cache "${_env}" "aws"
	fi
}
# }}}

# {{{ _obtain_credentials_nomad(hash_ref config, string env, int enabled)
_obtain_credentials_nomad() {
	declare -n _config="$1"; shift
	declare _env="$1"; shift
	declare -i _enabled="$1"; shift

	declare -a _nomad_cache=()

	if [[ ${_enabled} -eq 1 ]]; then
		_debug "Nomad auth"

		if [[ -z "${!_config[@]}" ]]; then
			_warn "Nomad configuration is not defined"
			return 1
		fi

		_check_cache "${_env}" "nomad"
		if [[ $? -gt 0 ]]; then
			if [[ "${_config[type]}" == "vault" ]]; then
				declare _vault_cache=""
				_cache_path _vault_cache "${_env}" "vault"
				if [[ -n "${_vault_cache}" && -f "${_vault_cache}" ]]; then
					. "${_vault_cache}"
				else
					_warn "Vault credentials is not found"
				fi
			fi

			declare -A _nomad_token=()
			_nomad_auth _nomad_token "${!_config}"
			if [[ $? -gt 0 ]]; then
				_warn "Failed to obtain Nomad token"
				return 1
			fi

			_debug "Nomad token successfully obtained"
			_nomad_cache=(
				"declare -x NOMAD_ADDR='${_config[server]}'"
				"declare -x NOMAD_TOKEN='${_nomad_token}'"
			)
		else
			_debug "Cached credentials for AWS still alive"
		fi
	else
		_debug "Nomad module disabled, unset environment"
		_nomad_cache=(
			"unset NOMAD_TOKEN NOMAD_ADDR"
		)
	fi

	if [[ -n "${_nomad_cache[@]}" ]]; then
		_cache_creds _nomad_cache "${_env}" "nomad"
	fi
}
# }}}

# {{{ _prepare_prompt(hash_ref config, string env, int enabled)
_prepare_prompt() {
	declare -n _config="$1"; shift
	declare _env="$1"; shift
	declare -i _enabled="$1"; shift

	declare -a _prompt_cache=(
	)

	if [[ ${_enabled} -eq 1 ]]; then
		_prompt_cache=(
			"declare -x WORK_ENV='[${_COLOR}${_env}${_NOCOLOR}]'"
		)
	else
		_prompt_cache=(
			"unset WORK_ENV"
		)
	fi

	_cache_creds _prompt_cache "${_env}" "prompt"
}
# }}}

# {{{ _prepare_banner(hash_ref config, string env, int enabled)
_prepare_banner() {
	declare -n _config="$1"; shift
	declare _env="$1"; shift
	declare -i _enabled="$1"; shift

	declare -a _banner=()

	if [[ ${_enabled} -eq 1 ]]; then
		if [[ -n "${_config[banner]}" ]]; then
			_banner=(
				"echo '${_config[banner]}'"
			)
		else
			_banner=(
				"echo '[/|\\] Environment ${_env} is loaded'"
			)
		fi
	fi

	if [[ -n "${_banner[@]}" ]]; then
		_cache_creds _banner "${_env}" "banner"
	fi
}
# }}}

# {{{ _prepare_custom_env(hash_ref config, stirng env, int enabled)
_prepare_custom_env() {
	declare -n _config="$1"; shift
	declare _env="$1"; shift
	declare -i _enabled="$1"; shift

	declare -a _custom_env_cache=()
	if [[ ${_enabled} -eq 1 ]]; then
		for i in ${!_config[@]}; do
			_custom_env_cache=(
				"${_custom_env_cache[@]}"
				"declare -x ${i}='${_config[${i}]}'"
			)
		done
	fi

	if [[ -n "${_custom_env_cache[@]}" ]]; then
		_cache_creds _custom_env_cache "${_env}" "custom_env"
	fi
}
# }}}

# {{{ _obtain_credentials(hash_ref config)
_obtain_credentials() {
	declare -n _config="$1"; shift
	declare _vault_cache=""

	_cache_creds _null "${_config_env}" "env"

	# {{{ Vault auth
	_obtain_credentials_vault _config_module_vault "${_config_env}" ${_config[vault]}
	# }}}

	# {{{ AWS auth
	_obtain_credentials_aws _config_module_aws "${_config_env}" ${_config[aws]}
	# }}}

	# {{{ Nomad auth
	_obtain_credentials_nomad _config_module_nomad "${_config_env}" ${_config[nomad]}
	# }}}

	# {{{ Custom env
	_prepare_custom_env _config_custom_env "${_config_env}" ${_config[custom_env]}
	# }}}

	# {{{ Prompt
	_prepare_prompt _null "${_config_env}" ${_config[prompt]}
	# }}}

	# {{{ Environment loading banner
	_prepare_banner _config_module_banner "${_config_env}" ${_config[banner]}
	# }}}
}
# }}}
# }}}
# }}}

# {{{ Check arguments
declare _env="$1"; shift

if [[ -z "${_env}" ]]; then
	_error "Environment is not specified"
fi

if [[ ! -f "${_CONFIG_DIR}/${_env}" ]]; then
	_debug "File ${_CONFIG_DIR}/${_env} is not found"
	_error "Configuration for ${_env} is not found"
fi
# }}}

# {{{ Load configuration
_debug "Load configuration for ${_env} environment"
. "${_CONFIG_DIR}/${_env}"

declare _config_env="${_env}"

_debug "Flush environment before run"
for e in ${_USED_ENVIRONMENT[@]}; do
	_debug "Unset ${e} variable"
	unset "${e}"
done
# }}}

# {{{ Preconfigure
declare _action="$1"; shift

if [[ -z "${_action}" ]]; then
	_action="all"
fi

case "${_action}" in
	all)
		_debug "Using modules configuration from config file"
		;;
	clear_cache)
		_debug "Clear cache for '${_env}'"
		_cache_clear "${_env}"
		exit $?
		;;
esac
# }}}

# {{{ Main routine
_obtain_credentials _config_modules
# }}}

# {{{ Print helper text about env loading
declare _global_cache=""
_cache_path _global_cache "${_env}" "env"
_debug "Now you can load environment
source '${_global_cache}'"
# }}}
