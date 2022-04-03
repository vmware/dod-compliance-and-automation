control 'PHTN-67-000087' do
  title "The Photon operating system must configure sshd to disallow Kerberos
authentication."
  desc  "If Kerberos is enabled through SSH, sshd provides a means of access to
the system's Kerberos implementation. Vulnerabilities in the system's Kerberos
implementation may then be subject to exploitation. To reduce the attack
surface of the system, the Kerberos authentication mechanism within SSH must be
disabled."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i KerberosAuthentication

    Expected result:

    KerberosAuthentication no

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/ssh/sshd_config with a text editor.

    Ensure that the \"KerberosAuthentication\" line is uncommented and set to
the following:

    KerberosAuthentication no

    At the command line, execute the following command:

    # service sshd reload
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-239158'
  tag rid: 'SV-239158r675282_rule'
  tag stig_id: 'PHTN-67-000087'
  tag fix_id: 'F-42328r675281_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command('sshd -T|&grep -i KerberosAuthentication') do
    its('stdout.strip') { should cmp 'KerberosAuthentication no' }
  end
end
