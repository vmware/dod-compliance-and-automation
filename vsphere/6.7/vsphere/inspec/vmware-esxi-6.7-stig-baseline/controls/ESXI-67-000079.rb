control 'ESXI-67-000079' do
  title "The ESXi host must not suppress warnings that the local or remote
shell sessions are enabled."
  desc  "Warnings that local or remote shell sessions are enabled alert
administrators to activity that they may not be aware of and need to
investigate."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Web Client, select the host and click Configure >> System
>> Advanced System Settings.

    Find the \"UserVars.SuppressShellWarning\" value and verify that it is set
to the following:

    0

    If the value is not set as above or does not exist, this is a finding.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning

    If the value returned is not \"0\" or the setting does not exist, this is a
finding.
  "
  desc 'fix', "
    From the vSphere Web Client, select the host and click Configure >> System
>> Advanced System Settings.

    Find the \"UserVars.SuppressShellWarning\" value and set it to the
following:

    0

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name UserVars.SuppressShellWarning |
Set-AdvancedSetting -Value \"0\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239329'
  tag rid: 'SV-239329r674916_rule'
  tag stig_id: 'ESXI-67-000079'
  tag fix_id: 'F-42521r674915_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name UserVars.SuppressShellWarning | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '0' }
  end
end
