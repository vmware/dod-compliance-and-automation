control 'PHTN-50-000214' do
  title 'The Photon operating system must configure Secure Shell (SSH) to disallow Kerberos authentication.'
  desc  "If Kerberos is enabled through SSH, sshd provides a means of access to the system's Kerberos implementation. Vulnerabilities in the system's Kerberos implementation may then be subject to exploitation. To reduce the attack surface of the system, the Kerberos authentication mechanism within SSH must be disabled."
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify the running configuration of sshd:

    # sshd -T|&grep -i KerberosAuthentication

    Example result:

    kerberosauthentication no

    If \"KerberosAuthentication\" is not set to \"no\", this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure the \"KerberosAuthentication\" line is uncommented and set to the following:

    KerberosAuthentication no

    At the command line, run the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-PHTN-50-000214'
  tag rid: 'SV-PHTN-50-000214'
  tag stig_id: 'PHTN-50-000214'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i KerberosAuthentication") do
    its('stdout.strip') { should cmp 'KerberosAuthentication no' }
  end
end
