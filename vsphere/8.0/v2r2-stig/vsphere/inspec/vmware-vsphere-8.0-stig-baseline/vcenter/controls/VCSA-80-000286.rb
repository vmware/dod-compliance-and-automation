control 'VCSA-80-000286' do
  title 'The vCenter Server must have Mutual Challenge Handshake Authentication Protocol (CHAP) configured for vSAN Internet Small Computer System Interface (iSCSI) targets.'
  desc 'When enabled, vSphere performs bidirectional authentication of both the iSCSI target and host. When not authenticating both the iSCSI target and host, the potential exists for a man-in-the-middle attack in which an attacker might impersonate either side of the connection to steal data. Bidirectional authentication mitigates this risk.'
  desc 'check', 'If no clusters are enabled for vSAN or if vSAN is enabled but iSCSI is not enabled, this is not applicable.

From the vSphere Client, go to Host and Clusters.

Select a vSAN Enabled Cluster >> Configure >> vSAN >> iSCSI Target Service.

For each iSCSI target, review the value in the "Authentication" column.

If the Authentication method is not set to "CHAP_Mutual" for any iSCSI target, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Host and Clusters.

Select a vSAN Enabled Cluster >> Configure >> vSAN >> iSCSI Target Service.

For each iSCSI target, select the item and click "Edit".

Change the "Authentication" field to "Mutual CHAP" and configure the incoming and outgoing users and secrets appropriately.'
  impact 0.5
  tag check_id: 'C-62693r934515_chk'
  tag severity: 'medium'
  tag gid: 'V-258953'
  tag rid: 'SV-258953r961863_rule'
  tag stig_id: 'VCSA-80-000286'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62602r934516_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  clusters = powercli_command('Get-Cluster | Where-Object {$_.VsanEnabled -eq $true} | Sort-Object Name | Select -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")

  setimpact = true
  if !clusters.empty?
    clusters.each do |cluster|
      iscsiEnabled = powercli_command("(Get-VsanClusterConfiguration -Cluster \"#{cluster}\").IscsiTargetServiceEnabled").stdout.strip
      if iscsiEnabled == 'True'
        command = "(Get-VsanClusterConfiguration -Cluster \"#{cluster}\").DefaultIscsiAuthenticationType"
        describe powercli_command(command) do
          its('stdout.strip') { should cmp 'MutualChap' }
        end
        setimpact = false
      else
        describe "vSAN iSCSI service not enabled on cluster: #{cluster}. This is not applicable." do
          skip "vSAN iSCSI service not enabled on cluster: #{cluster}. This is not applicable."
        end
      end
    end
  else
    describe 'No clusters with vSAN enabled found. This is not applicable.' do
      skip 'No clusters with vSAN enabled found. This is not applicable.'
    end
  end
  unless !setimpact
    impact 0.0
  end
end
