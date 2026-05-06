control 'UBTU-24-400030' do
  title 'Ubuntu 24.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts over SSH.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased.

Multifactor authentication requires using two or more factors to achieve authentication.

Factors include:
1) Something a user knows (e.g., password/PIN);
2) Something a user has (e.g., cryptographic identification device, token); and
3) Something a user is (e.g., biometric).

A privileged account is defined as an information system account with authorizations of a privileged user.

Network access is defined as access to an information system by a user (or a process acting on behalf of a user) communicating through a network (e.g., local area network, wide area network, or the internet).

The DOD common access card (CAC) with DOD-approved PKI is an example of multifactor authentication.

'
  desc 'check', 'Verify the sshd daemon allows public key authentication with the following command:

$ sudo grep -r ^PubkeyAuthentication /etc/ssh/sshd_config*
/etc/ssh/sshd_config:PubkeyAuthentication yes

If "PubkeyAuthentication" is not set to "yes", is commented out, is missing, or conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to use multifactor authentication for access to accounts.

Set the sshd option "PubkeyAuthentication" to "yes" in the "/etc/ssh/sshd_config" file.

PubkeyAuthentication yes'
  impact 0.5
  tag check_id: 'C-74755r1067129_chk'
  tag severity: 'medium'
  tag gid: 'V-270722'
  tag rid: 'SV-270722r1067130_rule'
  tag stig_id: 'UBTU-24-400030'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-74656r1066654_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766']
  tag nist: ['IA-2 (1)', 'IA-2 (2)']

  sshdcommand = input('sshdcommand')

  describe command("#{sshdcommand}|&grep -i PubkeyAuthentication") do
    its('stdout.strip') { should cmp 'PubkeyAuthentication yes' }
  end
end
