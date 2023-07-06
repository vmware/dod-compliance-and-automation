control 'TNDM-3X-000010' do
  title 'NSX-T Manager must restrict the use of configuration, administration, and the execution of privileged commands to authorized personnel based on organization-defined roles.'
  desc  "
    To mitigate the risk of unauthorized access, privileged access must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

    Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography.

    Controls for this requirement include prevention of non-privileged users from executing privileged functions to include disabling, circumventing, or altering implemented security safeguards/countermeasures; enforcing the use of organization-defined role-based access control policies over defined subjects and objects; and restricting access associated with changes to the system components.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX-T Manager web interface, go to System >> Users and Roles >> User Role Assignment.

    View each user and group and verify the role assigned to it.

    Application service account and user required privileges must be documented.

    If any user/group or service account are assigned to roles with privileges that are beyond those assigned by the SSP, this is a finding.
  "
  desc 'fix', "
    View the SSP to determine the required organization-defined roles and the least privilege policies required for each role. For example, audit administrator, crypto administrator, system administrator, etc. Assign users to roles based on SSP and least privileges. Carefully assign capabilities to each role based on SSP role assignments. To create a new role with reduced permissions, do the following:

    From the NSX-T Manager web interface, go to System >> Users and Roles >> Roles. Click \"Add Role\", provide a name and the required permissions, and then click \"Save\".

    To update user or group permissions to an existing role with reduced permissions, do the following:

    From the NSX-T Manager web interface, go to System >> Users and Roles >> User Role Assignment. Click the menu dropdown next to the target user or group and select \"Edit\". Remove the existing role, select the new one, and then click \"Save\".
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-APP-000033-NDM-000212'
  tag satisfies: ['SRG-APP-000340-NDM-000288', 'SRG-APP-000329-NDM-000287', 'SRG-APP-000340-NDM-000288']
  tag gid: 'V-251778'
  tag rid: 'SV-251778r851738_rule'
  tag stig_id: 'TNDM-3X-000010'
  tag fix_id: 'F-55192r810336_fix'
  tag cci: ['CCI-000213', 'CCI-000366', 'CCI-002169', 'CCI-002235']
  tag nist: ['AC-3', 'CM-6 b', 'AC-3 (7)', 'AC-6 (10)']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
