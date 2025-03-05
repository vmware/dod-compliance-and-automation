control 'VCSA-80-000278' do
  title 'The vCenter Server must use unique service accounts when applications connect to vCenter.'
  desc 'To not violate nonrepudiation (i.e., deny the authenticity of who is connecting to vCenter), when applications need to connect to vCenter they must use unique service accounts.'
  desc 'check', 'Verify each external application that connects to vCenter has a unique service account dedicated to that application.

For example, there should be separate accounts for Log Insight, Operations Manager, or anything else that requires an account to access vCenter.

If any application shares a service account that is used to connect to vCenter, this is a finding.'
  desc 'fix', 'For applications sharing service accounts, create a new service account to assign to the application so that no application shares a service account with another.

When standing up a new application that requires access to vCenter, always create a new service account prior to installation and grant only the permissions needed for that application.'
  impact 0.5
  tag check_id: 'C-62685r934491_chk'
  tag severity: 'medium'
  tag gid: 'V-258945'
  tag rid: 'SV-258945r961863_rule'
  tag stig_id: 'VCSA-80-000278'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-62594r934492_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
