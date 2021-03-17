# encoding: UTF-8

control 'ESXI-70-000003' do
  title 'The ESXi host must verify the exception users list for lockdown mode.'
  desc  "While a host is in lockdown mode (strict or normal), only users on the
\"Exception Users\" list are allowed access. These users do not lose their
permissions when the host enters lockdown mode. Usually you may want to add
service accounts such as a backup agent to the Exception Users list. Verify
that the list of users who are exempted from losing permissions is legitimate
and as needed per your environment. Adding unnecessary users to the exception
list defeats the purpose of lockdown mode."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Security Profile. Under Lockdown Mode, review the
Exception Users list.

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following script:

    $vmhost = Get-VMHost | Get-View
    $lockdown = Get-View $vmhost.ConfigManager.HostAccessManager
    $lockdown.QueryLockdownExceptions()

    If the Exception Users list contains accounts that do not require special
permissions, this is a finding.

    Note - The Exception Users list is empty by default and should remain that
way except under site specific circumstances.

    For environments that do not use vCenter server to manage ESXi, this is not
applicable.
  "
  desc  'fix', "From the vSphere Client go to Hosts and Clusters >> Select the
ESXi Host >> Configure >> System >> Security Profile. Under Lockdown Mode,
click Edit and remove unnecessary users from the exceptions list."
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000003'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')} | Get-View; (Get-View $vmhost.ConfigManager.HostAccessManager).QueryLockdownExceptions()"
  describe powercli_command(command) do
    its ('stdout.strip') { should cmp "#{input('exceptionUsers')}" }
  end

end

