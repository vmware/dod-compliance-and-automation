control 'ESXI-70-000080' do
  title 'The ESXi host must only run executables from approved VIBs.'
  desc  "vSphere Installation Bundles (VIBs) are the only method that binaries
and libraries should be introduced to the host. This controls what binaries are
present and capable of being run on the host itself. Combined with Secure Boot,
this ensures that every single process ever run on an ESXi host is signed,
allowed and expected.

    Note: This setting could cause issues with exotic troubleshooting steps or
certain plugins that SCP binaries to the host.
  "
  desc  'rationale', ''
  desc  'check', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"VMkernel.Boot.execInstalledOnly\" value and verify that it is set to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly

    If the \"VMkernel.Boot.execInstalledOnly\" setting is not set to \"true\"
or the setting does not exist, this is a finding.
  "
  desc  'fix', "
    Fom the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Advanced System Settings. Select the
\"VMkernel.Boot.execInstalledOnly\" value and set it to \"true\".

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command:

    Get-VMHost | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly |
Set-AdvancedSetting -Value \"true\"
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000080'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  command = "(Get-VMHost -Name #{input('vmhostName')}) | Get-AdvancedSetting -Name VMkernel.Boot.execInstalledOnly | Select-Object -ExpandProperty Value"
  describe powercli_command(command) do
    its('stdout.strip') { should cmp 'true' }
  end
end
