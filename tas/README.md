# Tanzu Application Service

## Overview

This project contains content for compliance remediation of the Tanzu Application Service(TAS) for Canonical Ubuntu STIGs.

## Using this Repo

This repos is split into 
- jammy-stig-compliance-release - BOSH release to fix STIG controls for Jammy Stemcell(ubuntu 22.04).
- xenial-compliance-release - BOSH release to fix STIG controls for Xenial Stemcell(ubuntu 16.04).
- \<VERSION\>/docs - TAS version specific upporting documentation will be made available here as needed.

## Disclaimer

VMware no liability for the consequences of applying specific configuration settings made on the basis of the SRGs/STIGs and Hardening Guides. It must be noted that the configuration settings specified should be evaluated in a local, representative test environment before implementation in a production environment, especially within large user populations. The extensive variety of environments makes it impossible to test these configuration settings for all potential software configurations.

For some production environments, failure to test before implementation may lead to a loss of required functionality. Evaluating the risks and benefits to a system’s particular circumstances and requirements is the system owner's responsibility. The evaluated risks resulting from not applying specified configuration settings must be approved by the responsible Authorizing Official.

Furthermore, VMware implies no warranty that the application of all specified configurations will make a system 100 percent secure. Security guidance is provided for the Department of Defense. While other agencies and organizations are free to use it, care must be given to ensure that all applicable security guidance is applied both at the device hardening level as well as the architectural level. Some of the controls may not be configurable in environments outside the DoDIN.

## License

The dod-compliance-and-automation project is available under the [Apache License, Version 2.0](LICENSE).
