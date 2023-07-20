# Ubuntu 20.04 STIG Hardning

Cookbook to automate STIG implementation for Ubuntu 20.04

## Cookbook variables:

Comnpensating controls may exist that satisfy the STIG requirement for a security measure.  
Variables definded in [vars.yml](vars/main.yml) allow skipping package insatallation where compensating controls exist.

|Name|Default|Description|
|----|:-------:|-----------|
|`install_fips`| `yes`|Install FIPs certified kernel, openssh, openssl and strongswan modules. Requires `UBUNTU_ADVANTAGE_PASSWORD` and `UBUNTU_ADVANTAGE_PASSWORD_UPDATES` variables to be set. There are **no compensating control** from FIPS STIG requirement. **Ubuntu 20.04 is not FIPS compliant/certified.**|
|`install_aide`| `yes`|`aide` is an open source host based file and directory integrity checker. `install_aide` can be set to `no` if any other integrity checker (e.g. Tripwire) is installed on the VM instead of being baked into the image.|
|`install_chrony`| `no`| `chrony` provides fast and accurate time synchronization. `install_chrony` can be set to `no` if any other time synching package (e.g. `timesyncd`) is used.|
|`install_audispd_plugins`|`yes`| `audispd_plugins` relays audit events to remote machines.  `audispd_plugins` can be set to `no` if any other mechanism of relaying logs to remote server (e.g fluentd) is being used.|
|`remove_existing_ca_certs`|`no`| STIG hardening requires `/etc/ssl/certs` only contain certificate files whose sha256 fingerprint match the fingerprint of DoD PKI-established certificate. If the value is set to `yes`, all other certficates under `/etc/ssl/certs` except DoD CA certs will be deleted.|
`run_sshd_banner`| `yes`| Replaces default ubuntu ssh login banner with [login banner specified by STIG](vars/main.yml)|
|`set_sshd_config_ciphers`|`yes`|Configure the SSH daemon to only implement FIPS-approved algorithms. |
|`set_sshd_config_macs`|`yes`|Configure the SSH daemon to only use Message Authentication Codes (MACs) that employ FIPS 140-2 approved ciphers. |
|`hold_packages`|`no`| k8s image-builder sets `apt-mark hold` on all installed packages preventing unintentional node images upgrades. This also prevents uninstalling unused packages by this playbook. Setting the value to `yes` will allow uninstalling unused packages and will also sets `apt-mark hold` on packages installed by this playbook |
|`UBUNTU_ADVANTAGE_PASSWORD`| |Env variable in `<USERNAME>:<PASSWORD>` format required to access Ubunutu `FIPS (ppa:ubuntu-advantage/fips)` private Personal Package Archive(ppa). Required if `install_fips` is set to `yes`.|
|`UBUNTU_ADVANTAGE_PASSWORD_UPDATES`| |Env variable in `<USERNAME>:<PASSWORD>` format required to access Ubunutu `FIPS Updates (ppa:ubuntu-advantage/fips-updates)` private Personal Package Archive(ppa). Required if `install_fips` is set to `yes`.|
|`UBUNTU_FIPS_SUBSCRIPTION_ID`| |Ubuntu Advantage(ua) Subscription ID. This environemnt variable can be used instead of `UBUNTU_ADVANTAGE_PASSWORD` and `UBUNTU_ADVANTAGE_PASSWORD_UPDATES`|