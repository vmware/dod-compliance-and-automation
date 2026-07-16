control 'UBTU-22-432010' do
  title 'Ubuntu 22.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.

'
  desc 'check', %q(Verify the "/etc/sudoers" file has no occurrences of "NOPASSWD" or "!authenticate" by using the following command:

$ sudo egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d/

If any occurrences of "!authenticate" return from the command, this is a finding.)
  desc 'fix', 'Remove any occurrence of "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  tag check_id: 'C-64287r1155199_chk'
  tag severity: 'medium'
  tag gid: 'V-260558'
  tag rid: 'SV-260558r1155216_rule'
  tag stig_id: 'UBTU-22-432010'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-64195r1155200_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157']
  tag 'documentable'
  tag cci: ['CCI-004895', 'CCI-002038']
  tag nist: ['SC-11 b', 'IA-11']

  describe command("egrep -iR '(!authenticate)' /etc/sudoers.d/ /etc/sudoers") do
    its('stdout.strip') { should be_empty }
  end
end
