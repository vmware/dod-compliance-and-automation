control 'PHTN-50-000133' do
  title 'The Photon operating system must require users to reauthenticate for privilege escalation.'
  desc  "
    Without re-authentication, users may access resources or perform tasks for which they do not have authorization.

    When operating systems provide the capability to escalate a functional capability, it is critical the user re-authenticate.
  "
  desc  'rationale', ''
  desc  'check', "
    This is not applicable to the following VCF components: Automation, Identity Broker, Operations, and Operations Cloud Proxy.

    At the command line, run the following commands to verify users with a set password are not allowed to sudo without re-authentication:

    # grep -ihs nopasswd /etc/sudoers /etc/sudoers.d/*|grep -vE '(^#|^%)'

    # awk -F: '($2 != \"x\" && $2 != \"!\") {print $1}' /etc/shadow

    If any account listed in the first output is also listed in the second output and is not documented, this is a finding.
  "
  desc 'fix', "
    Check the configuration of the \"/etc/sudoers\" and \"/etc/sudoers.d/*\" files with the following command:

    # visudo

    OR

    # visudo -f /etc/sudoers.d/<file name>

    Remove any occurrences of \"NOPASSWD\" tags associated with user accounts with a password hash.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-PHTN-50-000133'
  tag rid: 'SV-PHTN-50-000133'
  tag stig_id: 'PHTN-50-000133'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']

  # Find users with sudo privileges that do not require a password for escalation
  results = command('find /etc/sudoers /etc/sudoers.d/ -type f -exec grep -ihs nopasswd {} \; | grep -vE "(^#|^%)"').stdout.strip.split("\n")

  # Compare results to shadow file to verify their password is set to !
  if results.blank?
    describe 'Users with sudo privileges that do not require reauthentication' do
      subject { results }
      it { should be_blank }
    end
  else
    results.each do |result|
      # extract username from result
      user = result.split(' ')[0]
      # determine if sudo user has a password configured
      describe shadow.where(password: '!') do
        its('users') { should include(user) }
      end
    end
  end
end
