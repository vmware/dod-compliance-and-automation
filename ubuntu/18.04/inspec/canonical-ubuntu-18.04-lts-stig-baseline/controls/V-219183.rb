# encoding: UTF-8

control 'V-219183' do
  title "The Ubuntu operating system must allow the use of a temporary password
for system logons with an immediate change to a permanent password."
  desc  "Without providing this capability, an account may be created without a
password. Non-repudiation cannot be guaranteed once an account is created if a
user is not forced to change the temporary password upon initial logon.

    Temporary passwords are typically used to allow access when new accounts
are created or passwords are changed. It is common practice for administrators
to create temporary passwords for user accounts which allow the users to log
on, yet force them to change the password once they have successfully
authenticated.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify a policy exists that ensures when a user account is created, it is
created using a method that forces a user to change their password upon their
next login.

    If a policy does not exist, this is a finding.
  "
  desc  'fix', "
    Create a policy that ensures when a user is created, it is created using a
method that forces a user to change their password upon their next login.

    Below are two examples of how to create a user account that requires the
user to change their password upon their next login.

    # chage -d 0 [UserName]

    or

    # passwd -e [UserName]
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000380-GPOS-00165'
  tag gid: 'V-219183'
  tag rid: 'SV-219183r508662_rule'
  tag stig_id: 'UBTU-18-010112'
  tag fix_id: 'F-20907r304878_fix'
  tag cci: ['SV-109697', 'V-100593', 'CCI-002041']
  tag nist: ['IA-5 (1) (f)']

  describe 'Manual verification required' do
    skip 'Manually verify if a policy exists to ensure that a method exists to force temporary
      users to change their password upon next login'
  end
end

