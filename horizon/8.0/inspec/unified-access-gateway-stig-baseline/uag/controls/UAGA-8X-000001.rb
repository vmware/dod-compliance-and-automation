control 'UAGA-8X-000001' do
  title 'The UAG must enforce approved authorizations for logical access to information and system resources by employing identity-based, role-based, and/or attribute-based security policies.'
  desc  "
    Successful authentication must not automatically give an entity access to an asset or security boundary. The lack of authorization-based access control could result in the immediate compromise and unauthorized access to sensitive information. All DoD systems must be properly configured to incorporate access control methods that do not rely solely on authentication for authorized access.

    Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

    The UAG administrative interface provides two roles, a full administrative role, and a low-privilege administrator role that can perform a limited number of tasks such as read-only operations, system monitoring, downloading logs, and exporting configurations.

    Care must be taken to ensure that only authorized users are provided access to the UAG administrative interface, and the list of low-privilege administrator accounts is periodically reviewed for accuracy.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> Account Settings.  Click the \"Gear\" icon to edit.

    Verify the privileged accounts are configured and \"Enabled\" based on organizational roles.

    If the UAG contains any privileged accounts that are \"Enabled\" and do not conform to organizational roles, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to Advanced Settings >> Account Settings.  Click the \"Gear\" icon to edit.

    \"Enable\" or \"Disable\" each privileged account to conform to organizational roles.

    Click \"Save\" and \"Close\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000015-ALG-000016'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000001'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  result = uaghelper.runrestcommand('rest/v1/config/adminusers')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)

    admins = input('adminUsers')
    monitors = input('monitorUsers')

    users = jsoncontent['adminUsersList']

    users.each do |usr|
      if usr['roles'].include?('ROLE_ADMIN')
        describe 'Checking users with Admin Role' do
          subject { admins }
          it { should include usr['name'] }
        end
      else
        describe 'Checking users with Monitor Role' do
          subject { monitors }
          it { should include usr['name'] }
        end
      end
    end
  end
end
