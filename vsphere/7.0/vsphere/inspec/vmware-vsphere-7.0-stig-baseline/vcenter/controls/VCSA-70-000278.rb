control 'VCSA-70-000278' do
  title 'The vCenter Server must use unique service accounts when applications connect to vCenter.'
  desc  'In order to not violate non-repudiation (i.e., deny the authenticity of who is connecting to vCenter), when applications need to connect to vCenter they must use unique service accounts.'
  desc  'rationale', ''
  desc  'check', "
    Verify that each external application that connects to vCenter has a unique service account dedicated to that application.

    For example, there should be separate accounts for Log Insight, Operations Manager, or anything else that requires an account to access vCenter.

    If any application shares a service account that is used to connect to vCenter, this is a finding.
  "
  desc  'fix', "
    For applications sharing service accounts, create a new service account to assign to the application so that no application shares a service account with another.

    When standing up a new application that requires access to vCenter, always create a new service account prior to installation and grant only the permissions needed for that application.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000278'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
