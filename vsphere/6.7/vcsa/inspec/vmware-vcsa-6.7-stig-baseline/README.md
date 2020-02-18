# vmware-vcsa-6.7-stig-baseline
Inspec Profile to validate the secure configuration of VMware vCenter Service Appliance version 6.7 against the draft DISA vSphere 6.7 STIG
Version: 6.7.0 Draft

## VCSA Inspec Profiles

Inspec profiles for the VCSA are available for each component or can be run all or some from the wrapper/overlay profile.  Note the wrapper profile is setup to reference the other profiles from the same relative folder structure as seen here.  

[See the Inspec docs for more info on Profile dependencies and inheritence](https://www.inspec.io/docs/reference/profiles/)


## How to run Inspec locally from Powershell on Windows

**Note - assumes vcsa profiles are downloaded to C:\Inspec\Profiles\vmware-vcsa-6.7-stig-baseline**  
**Note - inputs are only needed for the Photon Profile**  

Run all profiles against a target vCenter appliance with needed inputs and output results to CLI
```
inspec exec C:\Inspec\Profiles\vmware-vcsa-6.7-stig-baseline\wrapper -t ssh://root@vcsa IP or FQDN --password 'password' --input syslogServer=test.local:514 photonIp=10.10.10.10 ntpServer1=time.test.local ntpServer2=time2.test.local
```

Run all profiles against a target vCenter appliance with needed inputs, show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-vcsa-6.7-stig-baseline\wrapper -t ssh://root@vcsa IP or FQDN --password 'password' --input syslogServer=test.local:514 photonIp=10.10.10.10 ntpServer1=time.test.local ntpServer2=time2.test.local --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json
```

Run a specific profile against a target vCenter appliance show progress, and output results to CLI and JSON
```
inspec exec C:\Inspec\Profiles\vmware-vcsa-6.7-stig-baseline\eam -t ssh://root@vcsa IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json
```

Run a specific profile (EAM in this case) against a target vCenter appliance show progress, and output results to CLI and JSON using the wrapper profile
```
inspec exec C:\Inspec\Profiles\vmware-vcsa-6.7-stig-baseline\wrapper -t ssh://root@vcsa IP or FQDN --password 'password' --show-progress --reporter=cli json:C:\Inspec\Reports\vcsa.json --controls=/VCEM/
```

Run a single STIG Control against a target vCenter appliance from a specific profile
```
inspec exec C:\Inspec\Profiles\vmware-vcsa-6.7-stig-baseline\eam -t ssh://root@vcsa IP or FQDN --password 'password' --controls=VCEM-67-000001
```

## Inspec Vendoring

When you execute a local profile, the inspec.yml file will be read in order to source any profile dependencies. It will then cache the dependencies locally and generate an inspec.lock file.

If you add or update dependencies in inspec.yml, dependencies may be re-vendored and the lockfile updated with inspec vendor --overwrite