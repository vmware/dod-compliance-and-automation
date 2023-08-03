control 'VCSA-70-000278' do
  title 'The vCenter Server must use unique service accounts when applications connect to vCenter.'
  desc 'To not violate nonrepudiation (i.e., deny the authenticity of who is connecting to vCenter), when applications need to connect to vCenter they must use unique service accounts.'
  desc 'check', 'Verify each external application that connects to vCenter has a unique service account dedicated to that application.

For example, there should be separate accounts for Log Insight, Operations Manager, or anything else that requires an account to access vCenter.

If any application shares a service account that is used to connect to vCenter, this is a finding.'
  desc 'fix', 'For applications sharing service accounts, create a new service account to assign to the application so that no application shares a service account with another.

When standing up a new application that requires access to vCenter, always create a new service account prior to installation and grant only the permissions needed for that application.'
  impact 0.5
  tag check_id: 'C-60033r885683_chk'
  tag severity: 'medium'
  tag gid: 'V-256358'
  tag rid: 'SV-256358r885685_rule'
  tag stig_id: 'VCSA-70-000278'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-59976r885684_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
