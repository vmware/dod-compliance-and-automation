control 'VRPA-8X-000009' do
  title 'The vRealize Operations Manager console must be secured after deployment.'
  desc  'After initial deployment the root password is blank and must be set upon initial login to the console.  Failure to do so could lead to an unauthorized individual setting this password or compromise of the appliance itself.'
  desc  'rationale', ''
  desc  'check', "
    Access the console of the vRealize Operations Manager appliance and attempt to login as root with a blank password.

    If the password for the root account has not been set, this is a finding.
  "
  desc 'fix', "
    Access the console of the vRealize Operations Manager appliance and login as root.

    When prompted for a password hit enter.

    When prompted for the old password hit enter.

    When prompted for the new password enter a new root password of appropriate length and complexity to meet organizational requirements.

    Re-enter the password to confirm and log out.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AS-000237'
  tag gid: 'V-VRPA-8X-000009'
  tag rid: 'SV-VRPA-8X-000009'
  tag stig_id: 'VRPA-8X-000009'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
