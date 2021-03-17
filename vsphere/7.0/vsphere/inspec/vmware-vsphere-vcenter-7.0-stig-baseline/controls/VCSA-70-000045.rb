# encoding: UTF-8

control 'VCSA-70-000045' do
  title "The vCenter Server must limit the maximum number of failed login
attempts to three."
  desc  "By limiting the number of failed login attempts, the risk of
unauthorized access via user password guessing, otherwise known as
brute-forcing, is reduced. Limits are imposed by locking the account."
  desc  'rationale', ''
  desc  'check', "
    From the vSphere Client, go to Administration >> Single Sign On >>
Configuration >> Local Accounts >> Lockout Policy.

    The following lockout policy should be set at follows:

    Maximum number of failed login attempts: 3

    If this account lockout policy is not configured as stated, this is a
finding.
  "
  desc  'fix', "From the vSphere Client, go to Administration >> Single Sign On
>> Configuration >> Local Accounts >> Lockout Policy. Click \"Edit\". Set the
Maximum number of failed login attempts to \"3\" and click \"Save\"."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000345'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCSA-70-000045'
  tag fix_id: nil
  tag cci: 'CCI-002238'
  tag nist: ['AC-7 b']

  describe "This check is a manual or policy based check" do
    skip "This must be reviewed manually"
  end

end

