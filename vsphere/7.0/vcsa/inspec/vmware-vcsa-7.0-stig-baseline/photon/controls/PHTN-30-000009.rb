# encoding: UTF-8

control 'PHTN-30-000009' do
  title 'The Photon operating system must configure sshd to use approved encryption algorithms.'
  desc  "Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

  OpenSSH on the Photon operating system is compiled with a FIPS validated cryptographic module. The \"FipsMode\" setting controls whether this module is initialaized and used in FIPS 140-2 mode or not.
  "
  desc  'rationale', ''
  desc  'check', "
  At the command line, execute the following command:

  # sshd -T|&grep -i FipsMode
  
  Expected result:
  
  FipsMode yes
  
  If the output does not match the expected result, this is a finding.
  "
  desc  'fix', "
  Open /etc/ssh/sshd_config with a text editor and ensure that the \"FipsMode\" line is uncommented and set to the following:

  FipsMode yes
  
  At the command line, execute the following command:
  
  # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag stig_id: 'PHTN-30-000009'
  tag cci: 'CCI-000068'
  tag nist: ['AC-17 (2)']

  describe command('sshd -T|&grep -i FipsMode') do
    its ('stdout.strip') { should cmp 'FipsMode yes' }
  end

end

