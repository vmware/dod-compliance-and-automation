control 'UBTU-24-300021' do
  title 'Ubuntu 24.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.'
  desc 'check', %q(Verify the "/etc/sudoers" file has no occurrences of "!authenticate" with the following command:

$ sudo egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d/

If any occurrences of "!authenticate" return from the command, this is a finding.)
  desc 'fix', 'Remove any occurrence of "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.'
  impact 0.5
  tag check_id: 'C-74740r1101784_chk'
  tag severity: 'medium'
  tag gid: 'V-270707'
  tag rid: 'SV-270707r1101786_rule'
  tag stig_id: 'UBTU-24-300021'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-74641r1101785_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe command("egrep -iR '(!authenticate)' /etc/sudoers.d/ /etc/sudoers") do
    its('stdout.strip') { should be_empty }
  end
end
