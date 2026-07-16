control 'VCFE-9X-000203' do
  title 'The ESX host must protect the confidentiality and integrity of transmitted information by isolating ESX management traffic.'
  desc  "
    The vSphere management network provides access to the vSphere management interface on each component. Services running on the management interface provide an opportunity for an attacker to gain privileged access to the systems. Any remote attack most likely would begin with gaining entry to this network.

    The management VMkernel port group can be on a standard or distributed virtual switch but must be on a dedicated network and must not be shared with any other functions.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> Networking >> VMkernel adapters.

    Review each VMkernel adapter that is used for management traffic and view the \"Enabled services\".

    If any services other than \"Management\" are enabled on the Management VMkernel adapter, this is a finding.

    If the network segment is accessible, except to networks where other management-related entities are located such as vCenter, this is a finding.

    If there are any other systems or devices such as VMs on the ESX management network, this is a finding.
  "
  desc 'fix', "
    To remove other enabled services from the ESX VMKernel port group used for management, do the following:

    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> Networking >> VMkernel adapters.

    Select the Management VMkernel and click \"Edit\". On the Port properties tab, uncheck all services except for \"Management\". Click \"OK\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000423-VMM-001700'
  tag gid: 'V-VCFE-9X-000203'
  tag rid: 'SV-VCFE-9X-000203'
  tag stig_id: 'VCFE-9X-000203'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']

  vmhostName = input('esx_vmhostName')
  cluster = input('esx_cluster')
  allhosts = input('esx_allHosts')
  vmhosts = []

  unless vmhostName.blank?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless cluster.blank?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")
  end

  if vmhosts.blank?
    describe 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.' do
      skip 'No ESX hosts found by name or in target vCenter...skipping test. Troubleshoot issue and rerun scan.'
    end
  else
    vmhosts.each do |vmhost|
      # Get all VMkernel interface names via esxcli to avoid vnetworking API issues
      vmks = powercli_command("$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name #{vmhost}) -V2; $esxcli.network.ip.interface.list.Invoke() | Select-Object -ExpandProperty Name").stdout.gsub("\r\n", "\n").split("\n")

      if vmks.blank?
        describe "No VMkernel interfaces found on #{vmhost} via esxcli...skipping test. Troubleshoot issue and rerun scan." do
          skip "No VMkernel interfaces found on #{vmhost} via esxcli...skipping test. Troubleshoot issue and rerun scan."
        end
      else
        vmks.each do |vmk|
          # Get the service tags for this VMkernel adapter
          tags = powercli_command("$esxcli = Get-EsxCli -VMHost (Get-VMHost -Name #{vmhost}) -V2; ($esxcli.network.ip.interface.tag.get.Invoke(@{interfacename='#{vmk}'})).Tags").stdout.strip

          next unless tags.include?('Management')

          # This VMkernel has Management enabled - check that no other services are also tagged on it
          non_mgmt_tags = tags.split(',').map(&:strip).reject { |t| t == 'Management' || t.empty? }

          describe "VMkernel #{vmk} on #{vmhost} management adapter service tags" do
            subject { non_mgmt_tags }
            it { should be_empty }
          end

          describe 'SA Interview' do
            skip 'SA also needs to confirm this VLAN is dedicated to Management and not shared with VMs or other services.'
          end
        end
      end
    end
  end
end
