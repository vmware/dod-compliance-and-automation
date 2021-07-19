# vmware-photon-3.0-stig-inspec-baseline
An InSpec Compliance Profile for Photon 3.0 VMware Appliance based deployments
Version: 3.0 Release 1 Version 2 STIG Readiness Guide

This content can be adapted to an open source Photon installation if the necessary packages are installed that the controls need.

## Running Inspec

**Note - commands assume you have download the profile and are in the profile folder**  

Run all controls against a target Photon OS server with example inputs and output results to CLI
```
inspec exec . -t ssh://root@photon IP or FQDN --password 'password' --input syslogServer=test.local:514 photonIp=10.10.10.10 ntpServer1=time.test.local ntpServer2=time2.test.local
```

Run all profiles against a target Photon OS server with example inputs, show progress, and output results to CLI and JSON
```
inspec exec . -t ssh://root@photon IP or FQDN --password 'password' --input syslogServer=test.local:514 ntpServer1=time.test.local ntpServer2=time2.test.local --show-progress --reporter=cli json:path\to\report\photon.json
```

Run a single STIG Control against a target Photon OS server
```
inspec exec . -t ssh://root@photon IP or FQDN --password 'password' --input syslogServer=test.local:514 ntpServer1=time.test.local ntpServer2=time2.test.local --controls=PHTN-30-000001
```

## Misc

Please review the inspec.yml for input variables that are specific to your environment.

## Viewing Results

InSpec results can be viewed from the CLI, saved to a file just as HTML or JSON, or visualized with a separate tool online such as [MITRE's Heimdall](https://heimdall-lite.mitre.org/). See https://github.com/mitre/heimdall for more details for offline options.

## InSpec Profile Overlays

If changes are needed to skip controls or update checks it is recommended to create an overlay profile that has a dependency on this profile with the needed changes so they can be easily tracked 

[See the InSpec docs for more info on Profile dependencies and inheritence](https://www.inspec.io/docs/reference/profiles/)
