control 'CFAP-4X-000005' do
  title 'SDDC Manager must not be exposed directly to the internet.'
  desc  'Allowing access to the SDDC Manager appliance from the internet or externally to the organization could expose the server to denial of service attacks or other penetration attempts.'
  desc  'rationale', ''
  desc  'check', "
    Interview the SA to determine if the SDDC Manager is accessible from outside of the organization.

    If the SDDC Manager appliance is accessible from the internet or from outside of the organizations boundary, this is a finding.
  "
  desc 'fix', "
    Note that this fix refers to an entity outside the scope of SDDC Manager.

    SA should work with network or boundary team to ensure proper firewall rules or other mechanisms are in place to protect the SDDC Manager appliance from being accessible externally to the organization.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFAP-4X-000005'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
