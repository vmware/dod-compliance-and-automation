control 'V-219309' do
  title 'The Ubuntu operating system must use strong authenticators in
    establishing nonlocal maintenance and diagnostic sessions.'
  desc  "Nonlocal maintenance and diagnostic activities are those activities
    conducted by individuals communicating through a network, either an external network (e.g., the Internet)
    or an internal network. Local maintenance and diagnostic activities are those
    activities carried out by individuals physically present at the information system or
    information system component and not communicating across a network connection.
    Typically, strong authentication requires authenticators that are resistant to replay
    attacks and employ multifactor authentication. Strong authenticators include, for example,
    PKI where certificates are stored on a token protected by a password, passphrase, or biometric."
  impact 0.5
  tag "gtitle": "SRG-OS-000125-GPOS-00065"
  tag "gid": 'V-219309'
  tag "rid": "SV-219309r378958_rule"
  tag "stig_id": "UBTU-18-010414"
  tag "fix_id": "F-21038r305271_fix"
  tag "cci": [ "CCI-000877" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify the Ubuntu operating system is configured to use strong
    authenticators in the establishment of nonlocal maintenance and diagnostic maintenance.

    Check that \"UsePAM\" is set to yes in /etc/ssh/sshd_config:

    # grep UsePAM /etc/ssh/sshd_config

    UsePAM yes

    If \"UsePAM\" is not set to \"yes\", this is a finding.
  "
  desc 'fix', "Configure the Ubuntu operating system to use strong authentication
    when establishing nonlocal maintenance and diagnostic sessions.

    Add or modify the following line to /etc/ssh/sshd_config

    UsePAM yes
  "
  describe sshd_config do
    its('UsePAM') { should cmp 'yes' }
  end
end
