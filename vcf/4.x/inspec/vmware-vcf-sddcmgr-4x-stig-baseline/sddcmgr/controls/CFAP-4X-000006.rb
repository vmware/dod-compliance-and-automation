control 'CFAP-4X-000006' do
  title 'The SDDC Manager users must have the correct roles assigned.'
  desc  'Users and service accounts must only be assigned privileges they require. Least Privilege requires that these privileges must only be assigned if needed, to reduce risk of confidentiality, availability or integrity loss.'
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager UI, navigate to Administration >> Single Sign On.

    Review the Users and Groups assigned a role in SDDC Manager and verify the appropriate role is assigned.

    If any users or groups are assigned a role that includes more access than needed, this is a finding.
  "
  desc 'fix', "
    To remove a user or group, do the following:

    From the SDDC Manager UI, navigate to Administration >> select Single Sign On.

    Select the user or group in question and click \"Remove\".

    Click \"Delete\" to confirm the removal.

    Note: To update a user or groups role they must first be removed then added back to the system.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-CFAP-4X-000006'
  tag rid: 'SV-CFAP-4X-000006'
  tag stig_id: 'CFAP-4X-000006'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
