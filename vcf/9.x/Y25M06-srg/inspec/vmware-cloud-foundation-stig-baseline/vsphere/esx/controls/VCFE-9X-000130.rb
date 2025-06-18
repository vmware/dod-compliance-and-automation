control 'VCFE-9X-000130' do
  title 'The ESX Image Profile and vSphere Installation Bundle (VIB) acceptance level must be verified.'
  desc  "
    Verify the ESX Image Profile to only allow signed VIBs. An unsigned VIB represents untested code installed on an ESX host. The ESX Image profile supports four acceptance levels:

    1. VMwareCertified - VIBs created, tested, and signed by VMware.
    2. VMwareAccepted - VIBs created by a VMware partner but tested and signed by VMware.
    3. PartnerSupported - VIBs created, tested, and signed by a certified VMware partner.
    4. CommunitySupported - VIBs that have not been tested by VMware or a VMware partner.

    Community Supported VIBs are not supported and do not have a digital signature. To protect the security and integrity of ESX hosts, do not allow unsigned (CommunitySupported) VIBs to be installed on hosts.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Security Profile.

    Under \"Host Image Profile Acceptance Level\" view the acceptance level.

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $esxcli.software.acceptance.get.Invoke()

    If the acceptance level is \"CommunitySupported\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the ESX Host >> Configure >> System >> Security Profile.

    Under \"Host Image Profile Acceptance Level\", click \"Edit\".

    Using the drop-down selection, set the acceptance level as \"VMwareCertified\", \"VMwareAccepted\", or \"PartnerSupported\". The default is \"PartnerSupported\".

    or

    From a PowerCLI command prompt while connected to the ESX host, run the following commands:

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.software.acceptance.set.CreateArgs()
    $arguments.level = \"PartnerSupported\"
    $esxcli.software.acceptance.set.Invoke($arguments)

    Note: \"VMwareCertified\" or \"VMwareAccepted\" may be substituted for \"PartnerSupported\", depending on local requirements. These are case sensitive.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000366-VMM-001430'
  tag satisfies: ['SRG-OS-000370-VMM-001460']
  tag gid: 'V-VCFE-9X-000130'
  tag rid: 'SV-VCFE-9X-000130'
  tag stig_id: 'VCFE-9X-000130'
  tag cci: ['CCI-001774', 'CCI-003992']
  tag nist: ['CM-14', 'CM-7 (5) (b)']

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
    list = ['PartnerSupported', 'VMwareCertified', 'VMwareAccepted']
    vmhosts.each do |vmhost|
      command = "$vmhost = Get-VMHost -Name #{vmhost}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.acceptance.get.Invoke()"
      describe powercli_command(command) do
        its('stdout.strip') { should be_in list }
      end
    end
  end
end
