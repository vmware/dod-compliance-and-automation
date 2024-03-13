control 'PHTN-40-000187' do
  title 'The Photon operating system must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created they do not have unnecessary access.'
  desc 'check', %q(At the command line, run the following command to verify the default umask configuration:

# grep '^UMASK' /etc/login.defs

Expected result:

UMASK 077

If the "UMASK" option is not set to "077", is missing or commented out, this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/login.defs

Add or update the following line:

UMASK 077'
  impact 0.5
  tag check_id: 'C-62596r933627_chk'
  tag severity: 'medium'
  tag gid: 'V-258856'
  tag rid: 'SV-258856r933629_rule'
  tag stig_id: 'PHTN-40-000187'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-62505r933628_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe login_defs do
    its('UMASK') { should cmp '077' }
  end
end
