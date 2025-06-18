# This file contains variables that are common to all STIG Remediation scripts

## Reporting
$ReportPath = "/tmp/reports"

## Connection Variables
$vcenter = ""

## ESX and VM targets
### For ESX remediation, specify a hostname or cluster. Order of precedence: hostname, cluster
### For VM remediation, specify a vmname, cluster, or allvms. Order of precedence: vmname, cluster, allvms
$hostname = ""
$cluster = ""
$vmname = ""
$allvms = $true
