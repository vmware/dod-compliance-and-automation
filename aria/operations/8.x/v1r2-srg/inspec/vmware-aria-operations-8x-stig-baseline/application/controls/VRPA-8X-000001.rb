control 'VRPA-8X-000001' do
  title 'vRealize Operations Manager must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc  "
    Strong access controls are critical to securing the application server. Access control policies (e.g., identity-based policies, role-based policies, attribute-based policies) and access enforcement mechanisms (e.g., access control lists, access control matrices, cryptography) must be employed by the application server to control access between users (or processes acting on behalf of users) and objects (e.g., applications, files, records, processes, application domains) in the application server.

    Without stringent logical access and authorization controls, an adversary may have the ability, with very little effort, to compromise the application server and associated supporting infrastructure.
  "
  desc  'rationale', ''
  desc  'check', "
    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Access Control.

    Review the User Accounts and User Groups tabs.

    If a user account or group is assigned access to resources that are not organization approved, then this is a finding.
  "
  desc 'fix', "
    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Access Control.

    Select the User Accounts or Roles tab and edit assigned roles or edit roles with assigned permissions.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag gid: 'V-VRPA-8X-000001'
  tag rid: 'SV-VRPA-8X-000001'
  tag stig_id: 'VRPA-8X-000001'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
