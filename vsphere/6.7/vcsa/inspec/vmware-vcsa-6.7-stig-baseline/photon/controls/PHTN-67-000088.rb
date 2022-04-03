control 'PHTN-67-000088' do
  title "The Photon operating system must configure sshd to use privilege
separation."
  desc  "Privilege separation in sshd causes the process to drop root
privileges when not needed, which would decrease the impact of software
vulnerabilities in the unprivileged section."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i UsePrivilegeSeparation

    Expected result:

    UsePrivilegeSeparation yes

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/ssh/sshd_config with a text editor.

    Ensure that the \"UsePrivilegeSeparation\" line is uncommented and set to
the following:

    UsePrivilegeSeparation yes

    At the command line, execute the following command:

    # service sshd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239159'
  tag rid: 'SV-239159r675285_rule'
  tag stig_id: 'PHTN-67-000088'
  tag fix_id: 'F-42329r675284_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('sshd -T|&grep -i UsePrivilegeSeparation') do
    its('stdout.strip') { should cmp 'UsePrivilegeSeparation yes' }
  end
end
