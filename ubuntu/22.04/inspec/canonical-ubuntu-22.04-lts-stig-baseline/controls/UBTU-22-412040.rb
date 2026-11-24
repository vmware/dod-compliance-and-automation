control 'UBTU-22-412040' do
  title 'Ubuntu 22.04 LTS must not assign an interactive login shell for system accounts.'
  desc 'Ensuring shells are not given to system accounts upon login makes it more difficult for attackers to use system accounts.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS system accounts do not have an interactive login shell with the following command:

Run the following command to list any system account (UID < 1000) that has an interactive shell, excluding authorized system utility accounts (root, sync, shutdown, halt):

$ awk -F: '(($3 > 0 && $3 < 1000) && $1 !~ /^(halt|sync|shutdown)$/ && $7 !~ /(nologin|false)$/) {print $1 ":" $3 ":" $7}' /etc/passwd

If the command returns any output, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS so that all noninteractive accounts on the system do not have an interactive shell assigned to them.

If the system account needs a shell assigned for mission operations, document the need with the information system security officer (ISSO).

Run the following command to disable the interactive shell for a specific noninteractive user account:

$ sudo usermod -s /usr/sbin/nologin <user>'
  impact 0.5
  tag check_id: 'C-93506r1261439_chk'
  tag severity: 'medium'
  tag gid: 'V-288817'
  tag rid: 'SV-288817r1261441_rule'
  tag stig_id: 'UBTU-22-412040'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag fix_id: 'F-93411r1261440_fix'
  tag 'documentable'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']

  findings = command("awk -F: '(($3 > 0 && $3 < 1000) && $1 !~ /^(halt|sync|shutdown)$/ && $7 !~ /(nologin|false)$/) {print $1 \":\" $3 \":\" $7}' /etc/passwd").stdout.split("\n")

  describe 'System accounts (UID < 1000) with an interactive login shell' do
    subject { findings }
    it { should be_empty }
  end
end
