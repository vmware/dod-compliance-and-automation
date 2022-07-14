control 'PHTN-30-000009' do
  title 'The Photon operating system must configure sshd to use approved encryption algorithms.'
  desc  "
    Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

    OpenSSH on the Photon operating system is compiled with a FIPS validated cryptographic module. The \"FipsMode\" setting controls whether this module is initialized and used in FIPS 140-2 mode.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i FipsMode

    Expected result:

    FipsMode yes

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"FipsMode\" line is uncommented and set to the following:

    FipsMode yes

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag satisfies: ['SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000423-GPOS-00187', 'SRG-OS-000396-GPOS-00176']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000009'
  tag cci: ['CCI-000068', 'CCI-001453', 'CCI-002890', 'CCI-002418', 'CCI-002450']
  tag nist: ['AC-17 (2)', 'AC-17 (2)', 'MA-4 (6)', 'SC-8', 'SC-13']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i FipsMode") do
    its('stdout.strip') { should cmp 'FipsMode yes' }
  end
end
