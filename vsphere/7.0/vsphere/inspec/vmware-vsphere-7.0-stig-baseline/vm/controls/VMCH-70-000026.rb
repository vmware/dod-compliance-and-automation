control 'VMCH-70-000026' do
  title 'Log size must be configured properly on the virtual machine (VM).'
  desc  "
    The ESXi hypervisor maintains logs for each individual VM by default. These logs contain information including but not limited to power events, system failure information, tools status and activity, time sync, virtual hardware changes, vMotion migrations, and machine clones.

    By default, the size of these logs is unlimited, and they are only rotated on vMotion or power events. This can cause storage issues at scale for VMs that do not vMotion or power cycle often.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, select the Virtual Machine, right click and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find the \"log.rotateSize\" value and verify it is set to \"2048000\".

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name log.rotateSize

    If the virtual machine advanced setting \"log.rotateSize\" does not exist or is not set to \"2048000\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the Virtual Machine, right click and go to Edit Settings >> VM Options tab >> Advanced >> Configuration Parameters >> Edit Configuration.

    Find the \"log.rotateSize\" value and set it to \"2048000\".

    Note: The VM must be powered off to configure the advanced settings through the vSphere Client. Therefore, it is recommended to configure these settings with PowerCLI as this can be done while the VM is powered on. Settings do not take effect via either method until the virtual machine is cold started, not rebooted.

    or

    From a PowerCLI command prompt while connected to the ESXi host or vCenter server, run the provided commands as noted below.

    If the setting does not exist, run:

    Get-VM \"VM Name\" | New-AdvancedSetting -Name log.rotateSize -Value 2048000

    If the setting exists, run:

    Get-VM \"VM Name\" | Get-AdvancedSetting -Name log.rotateSize | Set-AdvancedSetting -Value 2048000
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-256474'
  tag rid: 'SV-256474r886465_rule'
  tag stig_id: 'VMCH-70-000026'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vmName')
  allvms = input('allvms')
  vms = []

  unless vmName.empty?
    vms = powercli_command("Get-VM -Name #{vmName} | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if !vms.empty?
    vms.each do |vm|
      command = "Get-VM -Name '#{vm}' | Get-AdvancedSetting -Name log.rotateSize | Select-Object -ExpandProperty Value"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp '2048000' }
      end
    end
  else
    describe 'No VMs found!' do
      skip 'No VMs found...skipping tests'
    end
  end
end
