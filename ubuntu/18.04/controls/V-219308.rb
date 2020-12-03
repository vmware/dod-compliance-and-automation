control 'V-219308' do
  title "The Ubuntu operating system must enforce SSHv2 for network access to all accounts."
  desc  "A replay attack may enable an unauthorized user to gain access to the
    Ubuntu operating system. Authentication sessions between the authenticator and
    the Ubuntu operating system validating the user credentials must not be
    vulnerable to a replay attack.

    An authentication process resists replay attacks if it is impractical to
    achieve a successful authentication by recording and replaying a previous
    authentication message.

    A privileged account is any information system account with authorizations
    of a privileged user.

    Techniques used to address this include protocols using nonces (e.g.,
    numbers generated for a specific one-time use) or challenges (e.g., TLS,
    WS_Security). Additional techniques include time-synchronous or
    challenge-response one-time authenticators.
  "
  impact 0.8
  tag "gtitle": "SRG-OS-000112-GPOS-00057"
  tag "satisfies": nil
  tag "gid": 'V-219308'
  tag "rid": "SV-219308r378871_rule"
  tag "stig_id": "UBTU-18-010412"
  tag "fix_id": "F-21032r305253_fix"
  tag "cci": [ "CCI-001941","CCI-001942" ]
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
  desc 'check', "Verify that the Ubuntu operating system enforces SSH protocol
    2 for network access.

    Check the protocol versions that SSH allows with the following command:

    # grep Protocol /etc/ssh/sshd_config

    Protocol 2

    If the returned line allows for use of protocol \"1\", is commented out, or
    the line is missing, this is a finding.
  "
  desc 'fix', "Configure the Ubuntu operating system to enforce SSHv2 for
    network access to all accounts.

    Add or update the following line in the \"/etc/ssh/sshd_config\" file:

    Protocol 2

    Restart the ssh service.

    # systemctl restart sshd.service
  "
  describe sshd_config do
    its('Protocol') { should cmp 2 }
  end
end
