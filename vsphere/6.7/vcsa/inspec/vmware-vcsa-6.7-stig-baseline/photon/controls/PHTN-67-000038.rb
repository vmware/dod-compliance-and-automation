control 'PHTN-67-000038' do
  title "The Photon operating system must configure sshd to disconnect idle SSH
sessions."
  desc  "Terminating an idle session within a short time period reduces the
window of opportunity for unauthorized personnel to take control of a
management session enabled on the console or console port that has been left
unattended."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i ClientAliveInterval

    Expected result:

    ClientAliveInterval 900

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/ssh/sshd_config with a text editor.

    Ensure that the \"ClientAliveInterval\" line is uncommented and set to the
following:

    ClientAliveInterval 900

    At the command line, execute the following command:

    # service sshd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag gid: 'V-239110'
  tag rid: 'SV-239110r675138_rule'
  tag stig_id: 'PHTN-67-000038'
  tag fix_id: 'F-42280r675137_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  describe command('sshd -T|&grep -i ClientAliveInterval') do
    its('stdout.strip') { should cmp 'ClientAliveInterval 900' }
  end
end
