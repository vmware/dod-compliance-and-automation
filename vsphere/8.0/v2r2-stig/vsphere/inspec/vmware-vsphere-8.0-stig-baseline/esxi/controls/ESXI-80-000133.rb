control 'ESXI-80-000133' do
  title 'The ESXi Image Profile and vSphere Installation Bundle (VIB) acceptance level must be verified.'
  desc 'Verify the ESXi Image Profile to only allow signed VIBs. An unsigned VIB represents untested code installed on an ESXi host. The ESXi Image profile supports four acceptance levels:

1. VMwareCertified - VIBs created, tested, and signed by VMware.
2. VMwareAccepted - VIBs created by a VMware partner but tested and signed by VMware.
3. PartnerSupported - VIBs created, tested, and signed by a certified VMware partner.
4. CommunitySupported - VIBs that have not been tested by VMware or a VMware partner.

Community Supported VIBs are not supported and do not have a digital signature. To protect the security and integrity of ESXi hosts, do not allow unsigned (CommunitySupported) VIBs to be installed on hosts.'
  desc 'check', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Security Profile.

Under "Host Image Profile Acceptance Level" view the acceptance level.

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$esxcli.software.acceptance.get.Invoke()

If the acceptance level is "CommunitySupported", this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Hosts and Clusters.

Select the ESXi Host >> Configure >> System >> Security Profile.

Under "Host Image Profile Acceptance Level", click "Edit".

Using the drop-down selection, set the acceptance level as "VMwareCertified", "VMwareAccepted", or "PartnerSupported". The default is "PartnerSupported".

or

From a PowerCLI command prompt while connected to the ESXi host, run the following commands:

$esxcli = Get-EsxCli -v2
$arguments = $esxcli.software.acceptance.set.CreateArgs()
$arguments.level = "PartnerSupported"
$esxcli.software.acceptance.set.Invoke($arguments)

Note: "VMwareCertified" or "VMwareAccepted" may be substituted for "PartnerSupported", depending on local requirements. These are case sensitive.'
  impact 0.7
  tag check_id: 'C-62486r933297_chk'
  tag severity: 'high'
  tag gid: 'V-258746'
  tag rid: 'SV-258746r1003567_rule'
  tag stig_id: 'ESXI-80-000133'
  tag gtitle: 'SRG-OS-000366-VMM-001430'
  tag fix_id: 'F-62395r933298_fix'
  tag satisfies: ['SRG-OS-000366-VMM-001430', 'SRG-OS-000370-VMM-001460']
  tag cci: ['CCI-003992', 'CCI-001774']
  tag nist: ['CM-14', 'CM-7 (5) (b)']

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
    list = ['PartnerSupported', 'VMwareCertified', 'VMwareAccepted']
    vmhosts.each do |vmhost|
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.acceptance.get.Invoke()"
      describe powercli_command(command) do
        its('stdout.strip') { should be_in list }
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
