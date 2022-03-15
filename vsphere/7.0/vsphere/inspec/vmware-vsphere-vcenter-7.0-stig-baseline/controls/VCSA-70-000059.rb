control 'VCSA-70-000059' do
  title 'The vCenter Server must enable certificate based authentication.'
  desc  "The vCenter Client is capable of native CAC authentication. This
capability must be enabled and properly configured."
  desc  'rationale', ''
  desc  'check', "If vCenter is not configured to require CAC authentication,
either natively or through a federated identity provider, this is a finding."
  desc  'fix', "
    Configure CAC Authentication per supplemental document located at:

    https://core.vmware.com/resource/smart-card-authentication
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000059'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
