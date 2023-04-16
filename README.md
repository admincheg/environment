# Simple (not quiet) environment loader

Simple script, which prepares environment by config.
You can use authorize in Hashicorp Vault, Hashicorp Nomad, AWS.
Also you can predefine some envornment variables which will be prepared for load.

## Installation

So simple as possible. We place files to ${HOME}/.bin directory.
Also you should have installed Owllib, because this script uses it.
You can define PREFIX environment variable for change installation location.

    make install

## Configuration

There is no simple answer, but, you can read source code and use examples.
Script requires some applications for working, but you can disable functionality
by configuration.

Ok, let's dive, simple configuration

    declare -A _config_modules=(
        [aws]=1
        [vault]=1
        [nomad]=1
        [prompt]=1
        [banner]=1
        [custom_env]=1
    )
    declare -A _config_module_vault=(
        [type]="ldap"
        [role]="username"
        [secret]="SECRET"
        [server]="https://vault.local:8243"
    )
    declare -A _config_module_aws=(
        [type]="profile"
        [access_key]="default"
        [region]="eu-central-1"
    )
    declare -A _config_module_nomad=(
        [type]="vault"
        [server]="https://nomad.local:4646"
        [secret]="nomad"
        [role]="nomad-admin"
    )
    declare -A _config_custom_env=(
        [WORK_DIR]="/tmp"
        [SOME_ENVIRONMENT_VARIABLE]="${HOME}/.tmp"
    )

You should place it to ${HOME}/.config/env directory with some alphanumeric
name. For example environment1.

In the config above we declare which modules will be enabled.
Next we configure each module.

## Run

Run is pretty simple

    e environment1

After script successfully authorized in configured backends you'll get
information about loading prepared environment to your current session.


### ToDo

Prepare some additional documentation about project. I think nobody will use it,
but documentation is documentation. Some day, some day...
