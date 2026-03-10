control 'VCFA-9X-000331' do
  title 'The VMware Cloud Foundation vCenter Server must have Mutual Challenge Handshake Authentication Protocol (CHAP) enabled for the vSAN Internet Small Computer System Interface (iSCSI) target service.'
  desc  'When enabled, vSphere performs bidirectional authentication of both the iSCSI target and host. When not authenticating both the iSCSI target and host, the potential exists for a man-in-the-middle attack in which an attacker might impersonate either side of the connection to steal data. Bidirectional authentication mitigates this risk.'
  desc  'rationale', ''
  desc  'check', "
    If no clusters are enabled for vSAN or if vSAN is enabled but the iSCSI target service is not enabled, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select a vSAN Enabled Cluster >> Configure >> vSAN >> Services.

    Review the vSAN iSCSI Target Service configuration.

    If the default authentication type is not \"Mutual CHAP\", this is a finding.

    Next review any configured iSCSI targets to ensure they are configured for mutual CHAP.

    Select a vSAN Enabled Cluster >> Configure >> vSAN >> iSCSI Targets.

    For each iSCSI target, review the value in the \"Authentication\" column.

    If the Authentication method is not set to \"Mutual CHAP\" for any iSCSI target, this is a finding.
  "
  desc 'fix', "
    To configure a default authentication type for the vSAN iSCSI Target Service, do the following:

    From the vSphere Client, go to Hosts and Clusters.

    Select a vSAN Enabled Cluster >> Configure >> vSAN >> Services.

    Click Edit on the vSAN iSCSI Target Service tile.

    In the Authentication dropdown select \"Mutual CHAP\" and configure the incoming and outgoing user and secret fields then click Apply.

    To configure an iSCSI target with authentication different from the default authentication configuration, do the following:

    Select a vSAN Enabled Cluster >> Configure >> vSAN >> iSCSI Targets.

    Select the target iSCSI target and click Edit.

    In the Authentication dropdown select \"Mutual CHAP\" and configure the incoming and outgoing user and secret fields then click Apply.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: 'V-VCFA-9X-000331'
  tag rid: 'SV-VCFA-9X-000331'
  tag stig_id: 'VCFA-9X-000331'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  # Get all clusters with vSAN enabled
  clusters = powercli_command('Get-Cluster | Where-Object {$_.VsanEnabled -eq $true} | Sort-Object | Select-Object -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")

  if !clusters.blank?
    clusters.each do |cluster|
      command = "Get-Cluster -Name #{cluster} | Get-VsanClusterConfiguration | Select-Object Name,IscsiTargetServiceEnabled,DefaultIscsiAuthenticationType | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip
      resultjson = json(content: result)

      if result.blank?
        describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
          skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
        end
      elsif resultjson['IscsiTargetServiceEnabled'] == true
        # Check default authentication type
        # PowerCLI reports MutualChap for auth type but it gets translated to 0,1,2 in json 0=none, 1=chap,2=mutualchap
        describe "vSAN enabled cluster: #{cluster} with setting" do
          subject { json(content: result) }
          its(['IscsiTargetServiceEnabled']) { should cmp 'true' }
          its(['DefaultIscsiAuthenticationType']) { should cmp 2 }
        end

        # Check iSCSI targets
        targetcommand = "Get-VsanIscsiTarget -Cluster #{cluster} | Select-Object Cluster,IscsiQualifiedName,AuthenticationType | ConvertTo-Json -Depth 1 -WarningAction SilentlyContinue"
        targetresult = powercli_command(targetcommand).stdout.strip
        targetjson = json(content: targetresult)
        if targetresult.blank?
          describe 'No configured iSCSI targets found.' do
            subject { targetresult }
            it { should be_blank }
          end
        else
          targetjson.each do |target|
            describe "iSCSI Target: #{target['IscsiQualifiedName']} in cluster: #{cluster} with setting" do
              subject { target }
              its(['AuthenticationType']) { should cmp 2 }
            end
          end
        end
      else
        describe "vSAN enabled cluster: #{cluster} with setting" do
          subject { json(content: result) }
          its(['IscsiTargetServiceEnabled']) { should cmp 'false' }
        end
      end
    end
  else
    impact 0.0
    describe 'No clusters with vSAN enabled found. This is not applicable.' do
      skip 'No clusters with vSAN enabled found. This is not applicable.'
    end
  end
end
