control 'VRPA-8X-000045' do
  title 'The VMware Aria Operations server must use an enterprise user management system to uniquely identify and authenticate users (or processes acting on behalf of organizational users).'
  desc  "
    To assure accountability and prevent unauthorized access, application server users must be uniquely identified and authenticated.  This is typically accomplished via the use of a user store which is either local (OS-based) or centralized (LDAP) in nature.

    To ensure support to the enterprise, the authentication must utilize an enterprise solution.
  "
  desc  'rationale', ''
  desc  'check', "
    Review application server documentation and configuration settings to determine if the application server is using an enterprise solution to authenticate organizational users and processes running on behalf of organizational users.

    If an enterprise solution is not being used, this is a finding.
  "
  desc 'fix', 'Configure the application server to use an enterprise user management system to uniquely identify and authenticate users and processes acting on behalf of organizational users.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000148-AS-000101'
  tag gid: 'V-VRPA-8X-000045'
  tag rid: 'SV-VRPA-8X-000045'
  tag stig_id: 'VRPA-8X-000045'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
