control 'PHTN-40-000233' do
  title 'The Photon operating system must be configured to protect the Secure Shell (SSH) public host key from unauthorized modification.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', 'At the command line, run the following command:

# stat -c "%n permissions are %a and owned by %U:%G" /etc/ssh/*key.pub

Example result:

/etc/ssh/ssh_host_dsa_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_ecdsa_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_ed25519_key.pub permissions are 644 and owned by root:root
/etc/ssh/ssh_host_rsa_key.pub permissions are 644 and owned by root:root

If any "key.pub" file listed is not owned by root or not group owned by root or does not have permissions of "0644", this is a finding.'
  desc 'fix', 'At the command line, run the following commands for each returned file:

# chmod 644 <file>
# chown root:root <file>
# systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-62635r933744_chk'
  tag severity: 'medium'
  tag gid: 'V-258895'
  tag rid: 'SV-258895r933746_rule'
  tag stig_id: 'PHTN-40-000233'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-62544r933745_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  results = command('find /etc/ssh/ -maxdepth 1 -name "*key.pub"').stdout

  if !results.empty?
    results.split.each do |fname|
      describe file(fname) do
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
        its('mode') { should cmp '0644' }
      end
    end
  else
    describe 'No SSH public keys found to process.' do
      skip 'No SSH pucblic keys found to process.'
    end
  end
end
