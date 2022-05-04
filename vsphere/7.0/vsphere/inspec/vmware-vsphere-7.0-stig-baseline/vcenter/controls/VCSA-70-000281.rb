control 'VCSA-70-000281' do
  title 'The vCenter Server must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List by use of an external proxy server.'
  desc  'The vSAN Health Check is able to download the hardware compatibility list from VMware in order to check compliance against the underlying vSAN Cluster hosts. To ensure the vCenter server is not directly downloading content from the internet this functionality must be disabled or if this feature is necessary an external proxy server must be configured.'
  desc  'rationale', ''
  desc  'check', "
    If no clusters are enabled for vSAN, this is Not Applicable.

    From the vSphere Client, go to Host and Clusters >> Select the vCenter Server >>  Configure >> vSAN >> Internet Connectivity.

    If the HCL internet download is not required then ensure that \"Status\" is \"Disabled\".

    If the \"Status\" is \"Enabled\", this is a finding.

    If the HCL internet download is required then ensure that \"Status\" is \"Enabled\" and that a proxy host is configured.

    If \"Status\" is \"Enabled\" and a proxy is not configured, this is a finding.
  "
  desc 'fix', "
    From the vSphere Client, go to Host and Clusters >> Select the vCenter Server >>  Configure >> vSAN >> Internet Connectivity.

    Click \"Edit\".

    If the HCL internet download is not required then ensure that \"Status\" is \"Disabled\".

    If the HCL internet download is required then ensure that \"Status\" is \"Enabled\" and that a proxy host is appropriately configured.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000281'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
