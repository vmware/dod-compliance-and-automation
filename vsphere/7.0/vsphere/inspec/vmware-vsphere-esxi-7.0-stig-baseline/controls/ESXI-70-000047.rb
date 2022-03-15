control 'ESXI-70-000047' do
  title 'The ESXi Image Profile and VIB Acceptance Levels must be verified.'
  desc  "Verify the ESXi Image Profile to only allow signed VIBs. An unsigned
VIB represents untested code installed on an ESXi host. The ESXi Image profile
supports four acceptance levels:

    (1) VMwareCertified - VIBs created, tested and signed by VMware
    (2) VMwareAccepted - VIBs created by a VMware partner but tested and signed
by VMware,
    (3) PartnerSupported - VIBs created, tested and signed by a certified
VMware partner
    (4) CommunitySupported - VIBs that have not been tested by VMware or a
VMware partner.

    Community Supported VIBs are not supported and do not have a digital
signature. To protect the security and integrity of your ESXi hosts do not
allow unsigned (CommunitySupported) VIBs to be installed on your hosts.
  "
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client go to Hosts and Clusters >> Select the ESXi Host >>
Configure >> System >> Security Profile. Under \"Host Image Profile Acceptance
Level\" view the acceptance level.

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    $esxcli = Get-EsxCli -v2
    $esxcli.software.acceptance.get.Invoke()

    If the acceptance level is CommunitySupported, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client select the ESXi Host and go to Configure >> System
>> Security Profile. Under \"Host Image Profile Acceptance Level\", click
\"Edit...\" . Using the drop-down selection, set the acceptance level to be
VMwareCertified, VMwareAccepted, or PartnerSupported. The default is
PartnerSupported.

    or

    From a PowerCLI command prompt while connected to the ESXi host run the
following command(s):

    $esxcli = Get-EsxCli -v2
    $arguments = $esxcli.software.acceptance.set.CreateArgs()
    $arguments.level = \"PartnerSupported\"
    $esxcli.software.acceptance.set.Invoke($arguments)

    Note: VMwareCertified or VMwareAccepted may be substituted for
PartnerSupported, depending upon local requirements. These are also case
sensitive.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000366-VMM-001430'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000047'
  tag fix_id: nil
  tag cci: 'CCI-001749'
  tag nist: ['CM-5 (3)']

  list = %w(PartnerSupported VMwareCertified VMwareAccepted)
  command = "$vmhost = Get-VMHost -Name #{input('vmhostName')}; $esxcli = Get-EsxCli -VMHost $vmhost -V2; $esxcli.software.acceptance.get.Invoke()"
  describe powercli_command(command) do
    its('stdout.strip') { should be_in list }
  end
end
