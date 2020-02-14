control "PHTN-10-000067" do
  title "The Photon operating system must configure sshd to use prefered
ciphers."
  desc  "Privileged access contains control and configuration information and
is particularly sensitive, so additional protections are necessary. This is
maintained by using cryptographic mechanisms such as encryption to protect
confidentiality.

    Nonlocal maintenance and diagnostic activities are those activities
conducted by individuals communicating through a network, either an external
network (e.g., the Internet) or an internal network. Local maintenance and
diagnostic activities are those activities carried out by individuals
physically present at the information system or information system component
and not communicating across a network connection.

    This requirement applies to hardware/software diagnostic test equipment or
tools. This requirement does not cover hardware/software components that may
support information system maintenance, yet are a part of the system (e.g., the
software implementing \"ping,\" \"ls,\" \"ipconfig,\" or the hardware and
software implementing the monitoring port of an Ethernet switch).

    The operating system can meet this requirement through leveraging a
cryptographic module."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000394-GPOS-00174"
  tag gid: nil
  tag rid: "PHTN-10-000067"
  tag stig_id: "PHTN-10-000067"
  tag cci: "CCI-003123"
  tag nist: ["MA-4 (6)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# sshd -T|&grep -i Ciphers

Expected result:

ciphers
aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

If the output does not match the expected result, this is a finding.

"
  desc 'fix', "Open /etc/ssh/sshd_config with a text editor and ensure that the
\"Ciphers\" line is uncommented and set to the following:

Ciphers
aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

At the command line, execute the following command:

# service sshd reload"

  describe command('sshd -T|&grep -i ciphers') do
    its ('stdout.strip') { should cmp 'ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' }
  end

end

