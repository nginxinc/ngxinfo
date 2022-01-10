## NGINX Info
![ngxinfo](https://user-images.githubusercontent.com/8117589/148759796-25cd4d87-97d4-4056-b193-7c467f5817b3.gif)

The `ngxinfo` tool **reports on the suitability of upgrading any NGINX deployment to NGINX Plus**. It does this by analyzing the current configuration for anything not supported by NGINX Plus. The report provides any potential incompatibilities so that they can be investigated and any CVEs affecting the deployed version.

## Building ngxinfo

This repo is a _builder_ to produce the `ngxinfo.sh` shell script. We build the script so that it contains the most up-to-date information about NGINX modules, configuration directives, and CVEs. The resulting script has the following characteristics:

 * Completely open and non-obfuscated shell script
 * Does not require any 3rd party components other than standard POSIX tools
 * Can be run by any unprivileged user (non-root) that can read the nginx.conf file

To build the shell script clone this repository and run the build script.

### Install the dependencies for the build process
```shell
python3 -m pip install -r requirements.txt
```

If you would like to keep the dependencies isolated from your global python environment create and activate a virtual environment. This step is <b>NOT</b> mandatory. 

`python3 -m venv nginxinfo`
`source nginxinfo/bin/activate`

### Build the shell script
```shell
python3 build.py > ngxinfo.sh && chmod +x ngxinfo.sh
```

The generated shell script can be copied to the target server and executed.

## Running ngxinfo
Currently we support 3 runtime modes.
- normal (default) will print only important information for the upgrade.
- quiet (`-q`) will print nothing but return an exit code indicating upgrade risk.
- debug / verbose (`-v`) will print the configuration parsing output as well as all information printed in the normal mode.

#### Example output
```shell

(nginxinfo)$ ./nginxinfo.sh

  NGINX Info Report
  =================
  - Version: `ngxinfo v0.1 alpha`
  - Source: https://github.com/nginxinc/ngxinfo
  - Build date: 2021-12-05


  NGINX Version
  -------------

  - NGINX version: nginx-1.21.3
  - OpenSSL version: OpenSSL 1.0.2k-fips  26 Jan 2017
  - Provenance: CentOS Linux

  Configuration
  -------------

  NGINX is installed but not up and running. No network information available.
  - Found unsupported directives:
    - header_filter_by_lua_file (x1)
    - header_filter_by_lua_block (x1)

  Security
  --------

   ** Nothing found **

  Summary
  -------
  Do not upgrade to NGINX Plus without first discussing this project with your F5/NGINX representative
```

## ToDos

- More NGINX Version Information (source branch, release date)
- Calculate an Upgrade-Score based on different information (Operating system, unknown directives and/or modules)
- Scanning a `nginx -T` output and print a report
- Handle runtime information from /proc/PID/cmdline instead of `nginx -V`
- Detect unsupported builds and modules (dynamic and static)
