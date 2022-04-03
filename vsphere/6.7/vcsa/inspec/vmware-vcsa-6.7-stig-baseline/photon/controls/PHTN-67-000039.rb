control 'PHTN-67-000039' do
  title "The Photon operating system must configure sshd to disconnect idle SSH
sessions."
  desc  "Terminating an idle session within a short time period reduces the
window of opportunity for unauthorized personnel to take control of a
management session enabled on the console or console port that has been left
unattended."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i ClientAliveCountMax

    Expected result:

    ClientAliveCountMax 0

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/ssh/sshd_config with a text editor.

    Ensure that the \"ClientAliveCountMax\" line is uncommented and set to the
following:

    ClientAliveCountMax 0

    At the command line, execute the following command:

    # service sshd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag gid: 'V-239111'
  tag rid: 'SV-239111r675141_rule'
  tag stig_id: 'PHTN-67-000039'
  tag fix_id: 'F-42281r675140_fix'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']

  describe command('sshd -T|&grep -i ClientAliveCountMax') do
    its('stdout.strip') { should cmp 'ClientAliveCountMax 0' }
  end
end
