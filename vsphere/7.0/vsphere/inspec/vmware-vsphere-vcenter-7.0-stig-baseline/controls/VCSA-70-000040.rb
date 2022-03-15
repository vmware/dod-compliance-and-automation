control 'VCSA-70-000040' do
  title "The vCenter Server passwords must contain at least one uppercase
character."
  desc  "To enforce the use of complex passwords, minimum numbers of characters
of different classes are mandated. The use of complex passwords reduces the
ability of attackers to successfully obtain valid passwords using guessing or
exhaustive search techniques. Complexity requirements increase the password
search space by requiring users to construct passwords from a larger character
set than they may otherwise use."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >>
Configuration >> Local Accounts >> Password Policy.

    The following password requirement should be set with at least the stated
value:

    Upper-case Characters: At least 1

    If this password complexity policy is not configured as stated, this is a
finding.
  "
  desc 'fix', "From the vSphere Client, go to Administration >> Single Sign On
>> Configuration >> Local Accounts >> Password Policy. Click \"Edit\". Set
Upper-case Characters to at least \"1\" and click \"Save\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000166'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000040'
  tag fix_id: nil
  tag cci: 'CCI-000192'
  tag nist: ['IA-5 (1) (a)']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
