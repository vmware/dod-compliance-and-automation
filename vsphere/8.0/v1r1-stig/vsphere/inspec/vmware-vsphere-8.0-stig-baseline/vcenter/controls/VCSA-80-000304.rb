control 'VCSA-80-000304' do
  title 'The vCenter Server must enable data in transit encryption for vSAN.'
  desc 'Transit encryption must be enabled to prevent unauthorized disclosure information and to protect the confidentiality of organizational information.

vSAN data-in-transit encryption has the following characteristics:
-vSAN uses AES-256 bit encryption on data in transit.
-Forward secrecy is enforced for vSAN data-in-transit encryption.
-Traffic between data hosts and witness hosts is encrypted.
-File service data traffic between the VDFS proxy and VDFS server is encrypted.
-vSAN file services inter-host connections are encrypted.
-vSAN uses symmetric keys that are generated dynamically and shared between hosts. Hosts dynamically generate an encryption key when they establish a connection, and they use the key to encrypt all traffic between the hosts. You do not need a key management server to perform data-in-transit encryption.

Each host is authenticated when it joins the cluster, ensuring connections only to trusted hosts are allowed. When a host is removed from the cluster, it is authentication certificate is removed.

vSAN data-in-transit encryption is a cluster-wide setting. When enabled, all data and metadata traffic is encrypted as it transits across hosts.'
  desc 'check', 'If no clusters are enabled for vSAN, this is not applicable.

From the vSphere Client, go to Host and Clusters.

Select the vCenter Server >> Select the cluster >> Configure >> vSAN >> Services >> Data Services.

Review the "Data-in-transit encryption" status.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following commands:

$vsanclusterconf = Get-VsanView -Id VsanVcClusterConfigSystem-vsan-cluster-config-system
$vsanclusterconf.VsanClusterGetConfig((Get-Cluster -Name <cluster name>).ExtensionData.MoRef).DataInTransitEncryptionConfig

Repeat these steps for each vSAN enabled cluster in the environment.

If "Data-In-Transit encryption" is not enabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Host and Clusters.

Select the vCenter Server >> Select the target cluster >> Configure >> vSAN >> Services >> Data Services.

Click "Edit".

Enable "Data-In-Transit encryption" and choose a rekey interval suitable for the environment then click "Apply".'
  impact 0.5
  tag check_id: 'C-62709r934563_chk'
  tag severity: 'medium'
  tag gid: 'V-258969'
  tag rid: 'SV-258969r934565_rule'
  tag stig_id: 'VCSA-80-000304'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62618r934564_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Get all clusters with vSAN enabled
  clusters = powercli_command('Get-Cluster | Where-Object {$_.VsanEnabled -eq $true} | Sort-Object | Select-Object -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")

  if !clusters.empty?
    clusters.each do |cluster|
      command = "$vsanclusterconf = Get-VsanView -Id VsanVcClusterConfigSystem-vsan-cluster-config-system; $vsanclusterconf.VsanClusterGetConfig((Get-Cluster -Name #{cluster}).ExtensionData.MoRef).DataInTransitEncryptionConfig.Enabled"
      describe powercli_command(command) do
        its('stdout.strip') { should cmp 'true' }
      end
    end
  else
    describe 'No clusters with vSAN enabled found...skipping tests' do
      skip 'No clusters with vSAN enabled found...skipping tests'
    end
  end
end
