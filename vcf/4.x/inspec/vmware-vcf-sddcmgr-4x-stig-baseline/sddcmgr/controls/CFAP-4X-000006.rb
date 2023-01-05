control 'CFAP-4X-000006' do
  title 'SDDC Manager users must have the correct roles assigned.'
  desc  'Users and service accounts must only be assigned privileges they require. Least Privilege requires that these privileges must only be assigned if needed, to reduce risk of confidentiality, availability or integrity loss.'
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager UI navigate to Administration >> Users.

    Review the Users and Groups assigned a role in SDDC Manager and verify the appropriate role is assigned.

    If any users or groups are assigned a role that includes more access than needed, this is a finding.
  "
  desc 'fix', "
    From the SDDC Manager UI navigate to Administration >> select Users.

    Select the user or group in question and removed them or change their role to a more appropriate role.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'CFAP-4X-000006'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
