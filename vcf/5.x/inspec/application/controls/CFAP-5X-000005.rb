control 'CFAP-5X-000005' do
  title 'The SDDC Manager must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc  "
    Strong access controls are critical to securing the application server. Access control policies (e.g., identity-based policies, role-based policies, attribute-based policies) and access enforcement mechanisms (e.g., access control lists, access control matrices, cryptography) must be employed by the application server to control access between users (or processes acting on behalf of users) and objects (e.g., applications, files, records, processes, application domains) in the application server.

    Without stringent logical access and authorization controls, an adversary may have the ability, with very little effort, to compromise the application server and associated supporting infrastructure.
  "
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
  tag gtitle: 'SRG-APP-000033-AS-000024'
  tag satisfies: ['SRG-APP-000118-AS-000078', 'SRG-APP-000121-AS-000081', 'SRG-APP-000267-AS-000170', 'SRG-APP-000315-AS-000094', 'SRG-APP-000340-AS-000185', 'SRG-APP-000380-AS-000088']
  tag gid: 'V-CFAP-5X-000005'
  tag rid: 'SV-CFAP-5X-000005'
  tag stig_id: 'CFAP-5X-000005'
  tag cci: ['CCI-000162', 'CCI-000213', 'CCI-001314', 'CCI-001493', 'CCI-001813', 'CCI-002235', 'CCI-002314']
  tag nist: ['AC-17 (1)', 'AC-3', 'AC-6 (10)', 'AU-9', 'CM-5 (1)', 'SI-11 b']

  describe 'This is a manual or policy based check and must be manually reviewed.' do
    skip 'This is a manual or policy based check and must be manually reviewed.'
  end
end
