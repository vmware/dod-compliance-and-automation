control 'VCFV-9X-000214' do
  title 'Virtual machines (VMs) must remove unneeded floppy devices.'
  desc  'Ensure no device is connected to a virtual machine if it is not required. For example, floppy, serial, and parallel ports are rarely used for virtual machines in a data center environment, and CD/DVD drives are usually connected only temporarily during software installation.'
  desc  'rationale', ''
  desc  'check', "
    Floppy drives are no longer visible through the vSphere Client and must be configured via the Application Programming Interface (API) or PowerCLI.

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM | Get-FloppyDrive | Select Parent, Name, ConnectionState

    If a virtual machine has a floppy drive connected, this is a finding.
  "
  desc 'fix', "
    Floppy drives are no longer visible through the vSphere Client and must be configured via the Application Programming Interface (API) or PowerCLI.

    The VM must be powered off to remove a floppy drive.

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-FloppyDrive | Remove-FloppyDrive
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFV-9X-000214'
  tag rid: 'SV-VCFV-9X-000214'
  tag stig_id: 'VCFV-9X-000214'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmName = input('vm_Name')
  vmcluster = input('vm_cluster')
  allvms = input('vm_allvms')
  vms = []

  unless vmName.blank?
    vms = powercli_command("Get-VM -Name '#{vmName}' | Sort-Object Name | Select-Object -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless vmcluster.blank?
    vms = powercli_command("Get-VM -Location (Get-Cluster -Name '#{vmcluster}') | Sort-Object Name | Select-Object -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allvms == false
    vms = powercli_command('Get-VM | Sort-Object Name | Select-Object -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vms.blank?
    describe 'No virtual machines found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No virtual machines found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  else
    vms.each do |vm|
      command = "Get-VM -Name '#{vm}' | Get-FloppyDrive"
      result = powercli_command(command).stdout.strip
      describe "Checking the VM: #{vm} for Floppy drives" do
        subject { result }
        it { should be_blank }
      end
    end
  end
end
