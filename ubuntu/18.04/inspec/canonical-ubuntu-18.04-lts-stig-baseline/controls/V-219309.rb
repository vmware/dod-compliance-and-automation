# encoding: UTF-8

control 'V-219309' do
  title "The Ubuntu operating system must use strong authenticators in
establishing nonlocal maintenance and diagnostic sessions."
  desc  "Nonlocal maintenance and diagnostic activities are those activities
conducted by individuals communicating through a network, either an external
network (e.g., the Internet) or an internal network. Local maintenance and
diagnostic activities are those activities carried out by individuals
physically present at the information system or information system component
and not communicating across a network connection. Typically, strong
authentication requires authenticators that are resistant to replay attacks and
employ multifactor authentication. Strong authenticators include, for example,
PKI where certificates are stored on a token protected by a password,
passphrase, or biometric."
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system is configured to use strong
authenticators in the establishment of nonlocal maintenance and diagnostic
maintenance.

    Check that \"UsePAM\" is set to yes in /etc/ssh/sshd_config:

    # grep UsePAM /etc/ssh/sshd_config

    UsePAM yes

    If \"UsePAM\" is not set to \"yes\", this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to use strong authentication when
establishing nonlocal maintenance and diagnostic sessions.

    Add or modify the following line to /etc/ssh/sshd_config

    UsePAM yes
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag gid: 'V-219309'
  tag rid: 'SV-219309r508662_rule'
  tag stig_id: 'UBTU-18-010414'
  tag fix_id: 'F-21033r305256_fix'
  tag cci: ['SV-109945', 'V-100841', 'CCI-000877']
  tag nist: ['MA-4 c']

  describe sshd_config do
    its('UsePAM') { should cmp 'yes' }
  end
end

