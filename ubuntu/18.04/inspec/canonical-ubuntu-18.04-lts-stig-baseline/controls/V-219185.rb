# encoding: UTF-8

control 'V-219185' do
  title "The Ubuntu operating system must require users to re-authenticate for
privilege escalation and changing roles."
  desc  "Without re-authentication, users may access resources or perform tasks
for which they do not have authorization.

    When the Ubuntu operating system provides the capability to escalate a
functional capability or change security roles, it is critical the user
re-authenticate.


  "
  desc  'rationale', ''
  desc  'check', "
    Verify that \"/etc/sudoers\" has no occurrences of \"NOPASSWD\" or
\"!authenticate\".

    Check that the \"/etc/sudoers\" file has no occurrences of \"NOPASSWD\" or
\"!authenticate\" by running the following command:

    # sudo egrep -i '(nopasswd|!authenticate)' /etc/sudoers /etc/sudoers.d/*

    If any occurrences of \"NOPASSWD\" or \"!authenticate\" return from the
command, this is a finding.
  "
  desc  'fix', "Remove any occurrence of \"NOPASSWD\" or \"!authenticate\"
found in \"/etc/sudoers\" file or files in the /etc/sudoers.d directory."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157']
  tag gid: 'V-219185'
  tag rid: 'SV-219185r508662_rule'
  tag stig_id: 'UBTU-18-010114'
  tag fix_id: 'F-20909r304884_fix'
  tag cci: ['SV-109701', 'V-100597', 'CCI-002038']
  tag nist: ['IA-11']

  desc 'fix', "Remove any occurrence of \"NOPASSWD\" or \"!authenticate\" found
    in \"/etc/sudoers\" file or files in the /etc/sudoers.d directory.
  "
  describe command("egrep -r -i '(nopasswd|!authenticate)' /etc/sudoers.d/ /etc/sudoers") do
    its('stdout.strip') { should be_empty }
  end
end

