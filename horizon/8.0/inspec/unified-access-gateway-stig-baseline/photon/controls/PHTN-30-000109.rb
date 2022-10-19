control 'PHTN-30-000109' do
  title 'The Photon operating system must be configured to protect the SSH private host key from unauthorized access.'
  desc  'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # stat -c \"%n permissions are %a and owned by %U:%G\" /etc/ssh/*key

    Expected result:

    /etc/ssh/ssh_host_dsa_key permissions are 600 and owned by root:root
    /etc/ssh/ssh_host_ecdsa_key permissions are 600 and owned by root:root
    /etc/ssh/ssh_host_ed25519_key permissions are 600 and owned by root:root
    /etc/ssh/ssh_host_rsa_key permissions are 600 and owned by root:root

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command(s) for each returned file:

    # chmod 600 <file>
    # chown root:root <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000109'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  command('find /etc/ssh/ -maxdepth 1 -name "*key"').stdout.split.each do |fname|
    describe file(fname) do
      its('owner') { should cmp 'root' }
      its('group') { should cmp 'root' }
      its('mode') { should cmp '0600' }
    end
  end
end
