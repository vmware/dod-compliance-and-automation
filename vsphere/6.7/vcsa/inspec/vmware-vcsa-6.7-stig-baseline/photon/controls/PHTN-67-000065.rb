control 'PHTN-67-000065' do
  title "The Photon operating system must require users to reauthenticate for
privilege escalation."
  desc  "Without reauthentication, users may access resources or perform tasks
for which they do not have authorization.

    When operating systems provide the capability to escalate a functional
capability, it is critical the user reauthenticate.


  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following commands:

    # grep -ihs nopasswd /etc/sudoers /etc/sudoers.d/*|grep -v \"^#\"|grep -v
\"^%\"|awk '{print $1}'

    # awk -F: '($2 != \"x\" && $2 != \"!\") {print $1}' /etc/shadow

    If any account listed in the first output is also listed in the second
output, this is a finding.
  "
  desc 'fix', "
    Check the configuration of the \"/etc/sudoers\" and \"/etc/sudoers.d/*\"
files with the following command:

    # visudo
    OR
    # visudo -f /etc/sudoers.d/<file name>

    Remove any occurrences of \"NOPASSWD\" tags associated with user accounts
with a password hash.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157',
'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-239136'
  tag rid: 'SV-239136r675216_rule'
  tag stig_id: 'PHTN-67-000065'
  tag fix_id: 'F-42306r675215_fix'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']

  # Find users in sudoers with NOPASSWD flag and extract username
  results = command("awk '/NOPASSWD/ && /^[^#%].*/ {print $1}' /etc/sudoers").stdout.split("\n")

  # Compare results to shadow file to verify their password is set to !
  results.each do |result|
    describe shadow.where(password: '!') do
      its('users') { should include(result) }
    end
  end
end
