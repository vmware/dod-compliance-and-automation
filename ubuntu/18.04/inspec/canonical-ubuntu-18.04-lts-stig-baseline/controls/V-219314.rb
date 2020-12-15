# encoding: UTF-8

control 'V-219314' do
  title "The Ubuntu operating system must not allow unattended or automatic
login via ssh."
  desc  "Failure to restrict system access to authenticated users negatively
impacts Ubuntu operating system security."
  desc  'rationale', ''
  desc  'check', "
    Verify that unattended or automatic login via ssh is disabled.

    Check that unattended or automatic login via ssh is disabled with the
following command:

    # egrep '(Permit(.*?)(Passwords|Environment))' /etc/ssh/sshd_config

    PermitEmptyPasswords no
    PermitUserEnvironment no

    If \"PermitEmptyPasswords\" or \"PermitUserEnvironment\" keywords are not
set to \"no\", are missing completely, or they are commented out, this is a
finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to allow the SSH daemon to not allow
unattended or automatic login to the system.

    Add or edit the following lines in the \"/etc/ssh/sshd_config\" file:

    PermitEmptyPasswords no
    PermitUserEnvironment no

    In order for the changes to take effect, the SSH daemon must be restarted.

    # sudo systemctl restart sshd.service
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag gid: 'V-219314'
  tag rid: 'SV-219314r508662_rule'
  tag stig_id: 'UBTU-18-010424'
  tag fix_id: 'F-21038r305271_fix'
  tag cci: ['V-100851', 'SV-109955', 'CCI-000366']
  tag nist: ['CM-6 b']

  describe sshd_config do
    its('PermitEmptyPasswords') { should cmp 'no' }
    its('PermitUserEnvironment') { should cmp 'no' }
  end
end

