# encoding: UTF-8

control 'ESXI-70-000030' do
  title "The ESXi host must produce audit records containing information to
establish what type of events occurred."
  desc  "Without establishing what types of events occurred, it would be
difficult to establish, correlate, and investigate the events leading up to an
outage or attack."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"Config.HostAgent.log.level\" value and verify it is set to \"info\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level

    If the \"Config.HostAgent.log.level\" setting is not set to \"info\", this
is a finding.

    Note: Verbose logging level is acceptable for troubleshooting purposes.
  "
  desc  'fix', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Click \"Edit\". Select the
\"Config.HostAgent.log.level\" value and configure it to \"info\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    Get-VMHost | Get-AdvancedSetting -Name Config.HostAgent.log.level |
Set-AdvancedSetting -Value \"info\"
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000037-VMM-000150'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000030'
  tag fix_id: nil
  tag cci: 'CCI-000130'
  tag nist: ['AU-3']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Config.HostAgent.log.level | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its ('stdout.strip') { should match "info" }
  end

end

