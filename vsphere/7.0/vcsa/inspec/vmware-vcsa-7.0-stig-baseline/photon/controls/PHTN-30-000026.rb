# encoding: UTF-8

control 'PHTN-30-000026' do
  title "The Photon operating system must use OpenSSH for remote maintenance
sessions."
  desc  "Passwords need to be protected at all times, and encryption is the
standard method for protecting passwords. If passwords are not encrypted, they
can be plainly read (i.e., clear text) and easily compromised."
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # rpm -qa|grep openssh

    If there is no output or openssh is not >=  version 7.6, this is a finding.
  "
  desc  'fix', "Installing openssh manually is not supported by VMware. Revert
to a previous backup or redeploy the appliance."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag stig_id: 'PHTN-30-000026'
  tag cci: 'CCI-000197'
  tag nist: ['IA-5 (1) (c)']

  describe command("rpm -qa | grep 'openssh-server' | cut -f3 -d'-'") do
    its('stdout.strip') { should_not eq '' }
    its('stdout.strip') { should cmp >= '7.6' }
  end

end

