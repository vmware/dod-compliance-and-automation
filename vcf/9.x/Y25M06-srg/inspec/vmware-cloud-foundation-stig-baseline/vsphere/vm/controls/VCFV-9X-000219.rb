control 'VCFV-9X-000219' do
  title 'Virtual machines (VMs) must disable DirectPath I/O devices when not required.'
  desc  'VMDirectPath I/O (PCI passthrough) enables direct assignment of hardware PCI functions to VMs. This gives the VM access to the PCI functions with minimal intervention from the ESX host. This is a powerful feature for legitimate applications such as virtualized storage appliances, backup appliances, dedicated graphics, etc., but it also allows a potential attacker highly privileged access to underlying hardware and the PCI bus.'
  desc  'rationale', ''
  desc  'check', "
    For each virtual machine do the following:

    From the vSphere Client, view the Summary tab.

    Review the PCI devices section and verify none exist.

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-PassthroughDevice

    If the virtual machine has passthrough devices present, and the specific device returned is not approved, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, select the Virtual Machine, right-click and go to Edit Settings >> Virtual Hardware tab.

    Find the unexpected PCI device returned from the check.

    Hover the mouse over the device and click the circled \"X\" to remove the device. Click \"OK\".

    or

    From a PowerCLI command prompt while connected to the ESX host or vCenter server, run the following command:

    Get-VM \"VM Name\" | Get-PassthroughDevice | Remove-PassthroughDevice
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-VCFV-9X-000219'
  tag rid: 'SV-VCFV-9X-000219'
  tag stig_id: 'VCFV-9X-000219'
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
      command = "Get-VM -Name '#{vm}' | Get-PassthroughDevice"
      result = powercli_command(command).stdout.strip
      describe "Checking the VM: #{vm} for PCI passthrough devices" do
        subject { result }
        it { should be_blank }
      end
    end
  end
end
