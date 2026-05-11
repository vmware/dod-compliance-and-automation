control 'VCFA-9X-000191' do
  title 'The VMware Cloud Foundation vCenter Server must enable data at rest encryption for vSAN.'
  desc  "
    Applications handling data requiring \"data at rest\" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

    Data encryption is a common technique used in environments that require additional levels of security. It consists of a process to ensure that data can only be consumed by systems that have appropriate levels of access. Approved systems must have and use the appropriate cryptographic keys to encrypt and decrypt the data. Systems that do not have the keys will not be able to consume the data in any meaningful way, as it will remain encrypted in accordance with the commonly used Advanced Encryption Standard (AES) from the National Institute of Standards and Technology, or NIST.

    vSAN supports Data-At-Rest Encryption and Data-in-Transit Encryption and uses an AES 256 cipher. Data is encrypted after all other processing, such as deduplication, is performed. Data at rest encryption protects data on storage devices in case a device is removed from the cluster.
  "
  desc  'rationale', ''
  desc  'check', "
    If no clusters are enabled for vSAN, this is not applicable.

    From the vSphere Client, go to Hosts and Clusters.

    Select the vCenter Server >> Select the cluster >> Configure >> vSAN >> Services >> Data Services.

    Review the \"Data-at-rest encryption\" status.

    or

    From a PowerCLI command prompt while connected to the vCenter server, run the following command:

    Get-Cluster | Where-Object {$_.VsanEnabled -eq $true} | Get-VsanClusterConfiguration | Select-Object Name,EncryptionEnabled

    If \"Data-At-Rest encryption\" is not enabled, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Hosts and Clusters.

    Select the vCenter Server >> Select the target cluster >> Configure >> vSAN >> Services >> Data Services.

    Click \"Edit\".

    Enable \"Data-At-Rest encryption\" and select a pre-configured key provider from the drop down. Click \"Apply\".

    Note: Before enabling, read and understand the operational implications of enabling data at rest encryption in vSAN and how it affects capacity, performance, and recovery scenarios.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000428'
  tag gid: 'V-VCFA-9X-000191'
  tag rid: 'SV-VCFA-9X-000191'
  tag stig_id: 'VCFA-9X-000191'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']

  # Get all clusters with vSAN enabled
  clusters = powercli_command('Get-Cluster | Where-Object {$_.VsanEnabled -eq $true} | Sort-Object | Select-Object -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")

  if !clusters.blank?
    clusters.each do |cluster|
      command = "Get-Cluster -Name #{cluster} | Get-VsanClusterConfiguration | Select-Object Name,EncryptionEnabled | ConvertTo-Json -Depth 2 -WarningAction SilentlyContinue"
      result = powercli_command(command).stdout.strip

      if result.blank?
        describe "No results returned from command: #{command} . Troubleshoot issue and rerun scan." do
          skip "No results returned from command: #{command} . Troubleshoot issue and rerun scan."
        end
      else
        describe "vSAN enabled cluster: #{cluster}" do
          subject { json(content: result) }
          its(['EncryptionEnabled']) { should cmp 'true' }
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
