control 'VCSA-80-000196' do
  title 'The vCenter Server must enable data at rest encryption for vSAN.'
  desc 'Applications handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Data encryption is a common technique used in environments that require additional levels of security. It consists of a process to ensure that data can only be consumed by systems that have appropriate levels of access. Approved systems must have and use the appropriate cryptographic keys to encrypt and decrypt the data. Systems that do not have the keys will not be able to consume the data in any meaningful way, as it will remain encrypted in accordance with the commonly used Advanced Encryption Standard (AES) from the National Institute of Standards and Technology, or NIST.

vSAN supports Data-At-Rest Encryption and Data-in-Transit Encryption and uses an AES 256 cipher. Data is encrypted after all other processing, such as deduplication, is performed. Data at rest encryption protects data on storage devices in case a device is removed from the cluster.'
  desc 'check', 'If no clusters are enabled for vSAN, this is not applicable.

From the vSphere Client, go to Host and Clusters.

Select the vCenter Server >> Select the cluster >> Configure >> vSAN >> Services >> Data Services.

Review the "Data-at-rest encryption" status.

or

From a PowerCLI command prompt while connected to the vCenter server, run the following command:

Get-Cluster | Where-Object {$_.VsanEnabled -eq $true} | Get-VsanClusterConfiguration | Select-Object Name,EncryptionEnabled

If "Data-At-Rest encryption" is not enabled, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Host and Clusters.

Select the vCenter Server >> Select the target cluster >> Configure >> vSAN >> Services >> Data Services.

Click "Edit".

Enable "Data-At-Rest encryption" and select a pre-configured key provider from the drop down. Click "Apply".

Note: Before enabling, read and understand the operational implications of enabling data at rest encryption in vSAN and how it effects capacity, performance, and recovery scenarios.'
  impact 0.5
  tag check_id: 'C-62669r934443_chk'
  tag severity: 'medium'
  tag gid: 'V-258929'
  tag rid: 'SV-258929r934445_rule'
  tag stig_id: 'VCSA-80-000196'
  tag gtitle: 'SRG-APP-000428'
  tag fix_id: 'F-62578r934444_fix'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']

  # Get all clusters with vSAN enabled
  clusters = powercli_command('Get-Cluster | Where-Object {$_.VsanEnabled -eq $true} | Sort-Object | Select-Object -ExpandProperty Name').stdout.gsub("\r\n", "\n").split("\n")

  if !clusters.empty?
    clusters.each do |cluster|
      command = "Get-Cluster -Name #{cluster} | Get-VsanClusterConfiguration | Select-Object -ExpandProperty EncryptionEnabled"
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
