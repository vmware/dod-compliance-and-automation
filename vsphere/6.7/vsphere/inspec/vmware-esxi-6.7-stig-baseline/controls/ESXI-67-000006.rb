control 'ESXI-67-000006' do
  title "The ESXi host must enforce the unlock timeout of 15 minutes after a
user account is locked out."
  desc  "By enforcing a reasonable unlock timeout after multiple failed logon
attempts, the risk of unauthorized access via user password guessing, otherwise
known as brute forcing, is reduced. Users must wait for the timeout period to
elapse before subsequent logon attempts are allowed."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Advanced System Settings.

    Select the \"Security.AccountUnlockTime\" value and verify it is set to
\"900\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime

    If the \"Security.AccountUnlockTime\" is set to a value other than \"900\",
this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the ESXi host and go to Configure >> System
>> Advanced System Settings.

    Click \"Edit\" and select the \"Security.AccountUnlockTime\" value and
configure it to \"900\".

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name Security.AccountUnlockTime |
Set-AdvancedSetting -Value 900
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000329-VMM-001180'
  tag gid: 'V-239263'
  tag rid: 'SV-239263r674718_rule'
  tag stig_id: 'ESXI-67-000006'
  tag fix_id: 'F-42455r674717_fix'
  tag cci: ['CCI-002238']
  tag nist: ['AC-7 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name Security.AccountUnlockTime | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp '900' }
  end
end
