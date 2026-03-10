control 'VCSA-70-000281' do
  title 'The vCenter Server must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List (HCL) by use of an external proxy server.'
  desc 'The vSAN Health Check is able to download the HCL from VMware to check compliance against the underlying vSAN Cluster hosts. To ensure the vCenter server is not directly downloading content from the internet, this functionality must be disabled. If this feature is necessary, an external proxy server must be configured.'
  desc 'check', 'If no clusters are enabled for vSAN, this is not applicable.

From the vSphere Client, go to Host and Clusters.

Select the vCenter Server >> Configure >> vSAN >> Internet Connectivity.

If the HCL internet download is not required, verify "Status" is "Disabled".

If the "Status" is "Enabled", this is a finding.

If the HCL internet download is required, verify "Status" is "Enabled" and a proxy host is configured.

If "Status" is "Enabled" and a proxy is not configured, this is a finding.'
  desc 'fix', 'From the vSphere Client, go to Host and Clusters.

Select the vCenter Server >> Configure >> vSAN >> Internet Connectivity.

Click "Edit".

If the HCL internet download is not required, ensure "Status" is "Disabled".

If the HCL internet download is required, ensure "Status" is "Enabled" and a proxy host is appropriately configured.'
  impact 0.5
  tag check_id: 'C-60036r885692_chk'
  tag severity: 'medium'
  tag gid: 'V-256361'
  tag rid: 'SV-256361r885694_rule'
  tag stig_id: 'VCSA-70-000281'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-59979r885693_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
