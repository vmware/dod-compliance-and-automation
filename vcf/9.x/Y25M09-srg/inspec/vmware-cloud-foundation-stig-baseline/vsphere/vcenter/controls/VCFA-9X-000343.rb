control 'VCFA-9X-000343' do
  title 'The VMware Cloud Foundation vCenter Server must enable data in transit encryption for vSAN.'
  desc  "
    Transit encryption must be enabled to prevent unauthorized disclosure of information and to protect the confidentiality of organizational information.

    vSAN data-in-transit encryption has the following characteristics:
    -vSAN uses AES-256 bit encryption on data in transit.
    -Forward secrecy is enforced for vSAN data-in-transit encryption.
    -Traffic between data hosts and witness hosts is encrypted.
    -File service data traffic between the VDFS proxy and VDFS server is encrypted.
    -vSAN file services inter-host connections are encrypted.
    -vSAN uses symmetric keys that are generated dynamically and shared between hosts. Hosts dynamically generate an encryption key when they establish a connection, and they use the key to encrypt all traffic between the hosts. You do not need a key management server to perform data-in-transit encryption.

    Each host is authenticated when it joins the cluster, ensuring connections only to trusted hosts are allowed. When a host is removed from the cluster, its authentication certificate is removed.

    vSAN data-in-transit encryption is a cluster-wide setting. When enabled, all data and metadata traffic is encrypted as it transits across hosts.
  "
  desc  'rationale', ''
  desc  'check', "
    If no clusters are enabled for vSAN, this is not applicable.

    From the vSphere Client, go to Host and Clusters.

    Select the vCenter Server >> Select the cluster >> Configure >> vSAN >> Services >> Data Services.

    Review the \"Data-in-transit encryption\" status.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

    $vsanclusterconf = Get-VsanView -Id VsanVcClusterConfigSystem-vsan-cluster-config-system
    $vsanclusterconf.VsanClusterGetConfig((Get-Cluster -Name <cluster name>).ExtensionData.MoRef).DataInTransitEncryptionConfig

    Repeat these steps for each vSAN enabled cluster in the environment.

    If \"Data-In-Transit encryption\" is not enabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters.

    Select the vCenter Server >> Select the target cluster >> Configure >> vSAN >> Services >> Data Services.

    Click \"Edit\".

    Enable \"Data-In-Transit encryption\" and choose a rekey interval suitable for the environment then click \"Apply\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000343'
  tag rid: 'SV-VCFA-9X-000343'
  tag stig_id: 'VCFA-9X-000343'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Get all clusters with vSAN enabled
  clusters = powercli_command('Get-Cluster | Where-Object {$_.VsanEnabled -eq $true} | Sort-Object | Select-Object -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")

  unless clusters.blank?
    clusters.each do |cluster|
      command = "$vsanclusterconf = Get-VsanView -Id VsanVcClusterConfigSystem-vsan-cluster-config-system; $vsanclusterconf.VsanClusterGetConfig((Get-Cluster -Name #{cluster}).ExtensionData.MoRef).DataInTransitEncryptionConfig | ConvertTo-Json -Depth 1 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      if result.blank?
        describe "vSAN data in transit configuration on cluster: #{cluster}" do
          subject { result }
          it { should_not be_blank }
        end
      else
        resultjson = json(content: result)
        describe "vSAN data in transit configuration on cluster: #{cluster}" do
          subject { resultjson }
          its(['Enabled']) { should cmp 'true' }
        end
      end
    end
  end
end
