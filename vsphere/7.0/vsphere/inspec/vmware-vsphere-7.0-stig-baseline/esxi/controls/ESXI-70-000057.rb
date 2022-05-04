control 'ESXI-70-000057' do
  title 'The ESXi host must configure the firewall to block network traffic by default.'
  desc  'In addition to service-specific firewall rules, ESXi has a default firewall rule policy to allow or deny incoming and outgoing traffic. Reduce the risk of attack by making sure this is set to deny incoming and outgoing traffic.'
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # esxcli network firewall get

    If the \"Default Action\" does not equal \"DROP\", this is a finding.

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHostFirewallDefaultPolicy

    If the Incoming or Outgoing policies are \"True\", this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, run the following command(s):

    # esxcli network firewall set --default-action=false

    or

    From a PowerCLI command prompt while connected to the ESXi host, run the following command:

    Get-VMHostFirewallDefaultPolicy | Set-VMHostFirewallDefaultPolicy -AllowIncoming $false -AllowOutgoing $false
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000057'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    vmhosts.each do |vmhost|
      command = "Get-VMHost -Name #{vmhost} | Get-VMHostFirewallDefaultPolicy"
      describe powercli_command(command) do
        its('stdout.strip') { should_not match 'True' }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
