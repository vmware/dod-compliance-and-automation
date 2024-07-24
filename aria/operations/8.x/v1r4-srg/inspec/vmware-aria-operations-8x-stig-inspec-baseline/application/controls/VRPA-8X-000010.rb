control 'VRPA-8X-000010' do
  title 'VMware Aria Operations must not provide environment information to third parties.'
  desc  'Providing technical details about environmental infrastructure to third parties could unknowingly expose sensitive information to bad actors.'
  desc  'rationale', ''
  desc  'check', "
    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Global Settings.

    If the \"Customer Experience Improvement Program\" setting is not disabled, this is a finding.
  "
  desc 'fix', "
    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Global Settings.

    Select the \"Customer Experience Improvement Program\" line and click the edit icon.  Click the Disable button.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VRPA-8X-000010'
  tag rid: 'SV-VRPA-8X-000010'
  tag stig_id: 'VRPA-8X-000010'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
