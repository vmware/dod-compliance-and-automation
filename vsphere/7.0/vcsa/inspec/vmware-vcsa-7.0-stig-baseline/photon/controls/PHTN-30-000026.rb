control 'PHTN-30-000026' do
  title 'The Photon operating system must use an OpenSSH server version that does not support protocol 1.'
  desc  "
    A replay attack may enable an unauthorized user to gain access to the operating system. Authentication sessions between the authenticator and the operating system validating the user credentials must not be vulnerable to a replay attack.

    An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message.

    A privileged account is any information system account with authorizations of a privileged user.

    Techniques used to address this include protocols using nonces (e.g., numbers generated for a specific one-time use) or challenges (e.g., TLS, WS_Security). Additional techniques include time-synchronous or challenge-response one-time authenticators.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # rpm -qa|grep openssh

    If there is no output or openssh is not >=  version 7.4, this is a finding.
  "
  desc 'fix', 'Installing openssh manually is not supported by VMware for appliances. Revert to a previous backup or redeploy the appliance.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000074-GPOS-00042'
  tag satisfies: ['SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000395-GPOS-00175', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag gid: 'V-256503'
  tag rid: 'SV-256503r887183_rule'
  tag stig_id: 'PHTN-30-000026'
  tag cci: ['CCI-000197', 'CCI-000803', 'CCI-000877', 'CCI-001941', 'CCI-001942', 'CCI-002420', 'CCI-002422', 'CCI-002891']
  tag nist: ['IA-2 (8)', 'IA-2 (9)', 'IA-5 (1) (c)', 'IA-7', 'MA-4 (7)', 'MA-4 c', 'SC-8 (2)']

  describe command("rpm -qa | grep 'openssh-server' | cut -f3 -d'-'") do
    its('stdout.strip') { should_not eq '' }
    its('stdout.strip') { should cmp >= '7.4' }
  end
end
