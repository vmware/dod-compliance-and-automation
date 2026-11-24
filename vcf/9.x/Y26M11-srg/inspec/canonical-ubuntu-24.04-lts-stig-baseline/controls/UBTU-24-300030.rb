control 'UBTU-24-300030' do
  title 'Ubuntu 24.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created, they do not have unnecessary access.'
  desc 'check', %q(Verify Ubuntu 24.04 LTS defines default permissions for all authenticated users in such a way that the user can read and modify only their own files with the following command:

$ grep -i '^\s*umask' /etc/login.defs
UMASK 077

If the "UMASK" variable is set to "000", this is a finding with the severity raised to a CAT I.

If the value of "UMASK" is not set to "077", is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure the system to define the default permissions for all authenticated users in such a way that the user can read and modify only their own files.

Edit the "UMASK" parameter in the "/etc/login.defs" file to match the example below:

UMASK 077'
  impact 0.5
  tag check_id: 'C-74749r1066635_chk'
  tag severity: 'medium'
  tag gid: 'V-270716'
  tag rid: 'SV-270716r1066637_rule'
  tag stig_id: 'UBTU-24-300030'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-74650r1066636_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe login_defs do
    its('UMASK') { should eq '077' }
  end
end
