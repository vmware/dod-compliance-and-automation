control 'CDAP-10-000123' do
  title 'Cloud Director must disable the Customer Experience Improvement Program (CEIP).'
  desc  'The VMware CEIP sends VMware anonymized system information that is used to improve the quality, reliability, and functionality of VMware products and services. For confidentiality purposes, this feature must be disabled.'
  desc  'rationale', ''
  desc  'check', "
    Verify the CEIP is disabled by running the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool configure-ceip --status

    Example output:

    Participation disabled

    If the CEIP is enabled, this is a finding.
  "
  desc 'fix', "
    At the command prompt, execute the following command:

    # /opt/vmware/vcloud-director/bin/cell-management-tool configure-ceip --disable
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CDAP-10-000123'
  tag rid: 'SV-CDAP-10-000123'
  tag stig_id: 'CDAP-10-000123'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('/opt/vmware/vcloud-director/bin/cell-management-tool configure-ceip --status') do
    its('stdout.strip') { should cmp 'Participation disabled' }
  end
end
