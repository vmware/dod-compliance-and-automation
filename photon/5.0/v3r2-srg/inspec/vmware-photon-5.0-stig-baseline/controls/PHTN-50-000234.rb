control 'PHTN-50-000234' do
  title 'The Photon operating system must be configured to protect the Secure Shell (SSH) private host key from unauthorized access.'
  desc  'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # stat -c \"%n permissions are %a and owned by %U:%G\" /etc/ssh/*key

    Example result:

    /etc/ssh/ssh_host_dsa_key permissions are 600 and owned by root:root
    /etc/ssh/ssh_host_ecdsa_key permissions are 600 and owned by root:root
    /etc/ssh/ssh_host_ed25519_key permissions are 600 and owned by root:root
    /etc/ssh/ssh_host_rsa_key permissions are 600 and owned by root:root

    If any key file listed is not owned by root or not group owned by root or does not have permissions of \"0600\", this is a finding.
  "
  desc 'fix', "
    At the command line, run the following commands for each returned file:

    # chmod 600 <file>
    # chown root:root <file>
    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000234'
  tag rid: 'SV-PHTN-50-000234'
  tag stig_id: 'PHTN-50-000234'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  results = command('find /etc/ssh/ -maxdepth 1 -name "*key"').stdout

  if !results.empty?
    results.split.each do |fname|
      describe file(fname) do
        its('owner') { should cmp 'root' }
        its('group') { should cmp 'root' }
        its('mode') { should cmp '0600' }
      end
    end
  else
    describe 'No SSH keys found to process.' do
      skip 'No SSH keys found to process.'
    end
  end
end
