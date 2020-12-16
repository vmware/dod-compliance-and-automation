# encoding: UTF-8

control 'V-219308' do
  title "The Ubuntu operating system must enforce SSHv2 for network access to
all accounts."
  desc  "A replay attack may enable an unauthorized user to gain access to the
operating system. Authentication sessions between the authenticator and the
operating system validating the user credentials must not be vulnerable to a
replay attack.

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
  desc  'rationale', ''
  desc  'check', "
    Verify that the Ubuntu operating system enforces SSH protocol 2 for network
access.

    Check the protocol versions that SSH allows with the following command:

    # grep Protocol /etc/ssh/sshd_config

    Protocol 2

    If the returned line allows for use of protocol \"1\", is commented out, or
the line is missing, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to enforce SSHv2 for network access
to all accounts.

    Add or update the following line in the \"/etc/ssh/sshd_config\" file:

    Protocol 2

    Restart the ssh service.

    # systemctl restart sshd.service
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag satisfies: ['SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag gid: 'V-219308'
  tag rid: 'SV-219308r508662_rule'
  tag stig_id: 'UBTU-18-010412'
  tag fix_id: 'F-21032r305253_fix'
  tag cci: ['SV-109943', 'V-100839', 'CCI-001941', 'CCI-001942']
  tag nist: ['IA-2 (8)', 'IA-2 (9)']

  describe sshd_config do
    its('Protocol') { should cmp 2 }
  end
end

