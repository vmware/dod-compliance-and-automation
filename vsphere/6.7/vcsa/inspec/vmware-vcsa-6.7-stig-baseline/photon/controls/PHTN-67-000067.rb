control 'PHTN-67-000067' do
  title "The Photon operating system must configure sshd to use FIPS 140-2
ciphers."
  desc  "Privileged access contains control and configuration information and
is particularly sensitive, so additional protections are necessary. This is
maintained by using cryptographic mechanisms such as encryption to protect
confidentiality.

    Nonlocal maintenance and diagnostic activities are activities conducted by
individuals communicating through a network, either an external network (e.g.,
the internet) or an internal network. Local maintenance and diagnostic
activities are activities carried out by individuals physically present at the
information system or information system component and not communicating across
a network connection.

    This requirement applies to hardware/software diagnostic test equipment or
tools. This requirement does not cover hardware/software components that may
support information system maintenance, yet are a part of the system (e.g., the
software implementing \"ping,\" \"ls,\" \"ipconfig,\" or the hardware and
software implementing the monitoring port of an Ethernet switch).

    The operating system can meet this requirement through leveraging a
cryptographic module.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i Ciphers

    Expected result:

    ciphers
aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Open /etc/ssh/sshd_config with a text editor.

    Ensure that the \"Ciphers\" line is uncommented and set to the following:

    Ciphers
aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

    At the command line, execute the following command:

    # service sshd reload
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000394-GPOS-00174'
  tag satisfies: ['SRG-OS-000394-GPOS-00174', 'SRG-OS-000424-GPOS-00188',
'SRG-OS-000478-GPOS-00223']
  tag gid: 'V-239138'
  tag rid: 'SV-239138r816640_rule'
  tag stig_id: 'PHTN-67-000067'
  tag fix_id: 'F-42308r675221_fix'
  tag cci: ['CCI-002421', 'CCI-002450', 'CCI-003123']
  tag nist: ['SC-8 (1)', 'SC-13', 'MA-4 (6)']

  describe command('sshd -T|&grep -i ciphers') do
    its('stdout.strip') { should cmp 'ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' }
  end
end
