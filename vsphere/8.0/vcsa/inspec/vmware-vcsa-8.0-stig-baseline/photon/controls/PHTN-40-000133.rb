control 'PHTN-40-000133' do
  title 'The Photon operating system must require users to reauthenticate for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.

When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.'
  desc 'check', %q(At the command line, run the following commands to verify users with a set password are not allowed to sudo without reauthentication:

# grep -ihs nopasswd /etc/sudoers /etc/sudoers.d/*|grep -vE '(^#|^%)'

# awk -F: '($2 != "x" && $2 != "!") {print $1}' /etc/shadow

If any account listed in the first output is also listed in the second output and is not documented, this is a finding.)
  desc 'fix', 'Check the configuration of the "/etc/sudoers" and "/etc/sudoers.d/*" files with the following command:

# visudo

OR

# visudo -f /etc/sudoers.d/<file name>

Remove any occurrences of "NOPASSWD" tags associated with user accounts with a password hash.'
  impact 0.5
  tag check_id: 'C-62587r933600_chk'
  tag severity: 'medium'
  tag gid: 'V-258847'
  tag rid: 'SV-258847r933602_rule'
  tag stig_id: 'PHTN-40-000133'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag fix_id: 'F-62496r933601_fix'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']

  # Find users in sudoers with NOPASSWD flag and extract username
  results = command("awk '/NOPASSWD/ && /^[^#%].*/ {print $1}' /etc/sudoers /etc/sudoers.d/*").stdout.split("\n")

  # Compare results to shadow file to verify their password is set to !
  if !results.empty?
    results.each do |result|
      describe shadow.where(password: '!') do
        its('users') { should include(result) }
      end
    end
  else
    impact 0.0
    describe 'No users found in sudoers with NOPASSWD flag...skipping...' do
      skip 'No users found in sudoers with NOPASSWD flag...skipping...'
    end
  end
end
