control 'VMCH-70-000027' do
  title 'Log retention must be properly configured on the virtual machine.'
  desc  "
    The ESXi hypervisor maintains logs for each individual VM by default. These logs contain information including, but not limited to, power events, system failure information, tools status and activity, time sync, virtual hardware changes, vMotion migrations and machine clones.

    By default, ten of these logs are retained. This is normally sufficient for most environments but this configuration must be verified and maintained.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client select the Virtual Machine, right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find the \"log.keepOld\" value and verify it is set to \"10\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name log.keepOld

    If the virtual machine advanced setting \"log.keepOld\" is not set to \"10\", this is a finding.

    If the virtual machine advanced setting \"log.keepOld\" does not exist, this is not a finding.
  "
  desc 'fix', "
    From the vSphere Client select the Virtual Machine, right click and go to Edit Settings >> VM Options Tab >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find the \"log.keepOld\" value and set it to \"10\".

    Note: The VM must be powered off to modify the advanced settings through the vSphere Client. It is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. In this case, the modified settings will not take effect until a cold boot of the VM.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    If the setting does not exist, run:

    Get-VM \"VM Name\" | New-AdvancedSetting -Name log.keepOld -Value 10

    If the setting exists, run:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name log.keepOld | Set-AdvancedSetting -Value 10
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VMCH-70-000027'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vmName')
  allvms = input('allvms')
  vms = []

  unless vmName.empty?
    vms = powercli_command("Get-VM -Name #{vmName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vms.empty?
    vms.each do |vm|
      command = "Get-VM -Name #{vm} | Get-AdvancedSetting -Name log.keepOld | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '10' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
