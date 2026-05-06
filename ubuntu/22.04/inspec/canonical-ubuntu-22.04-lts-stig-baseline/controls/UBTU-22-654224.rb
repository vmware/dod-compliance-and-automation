control 'UBTU-22-654224' do
  title 'The operating system must restrict privilege elevation to authorized personnel.'
  desc 'If the "sudoers" file is not configured correctly, any user defined on the system can initiate privileged actions on the target system.'
  desc 'check', "Verify the operating system restricts privilege elevation to authorized personnel with the following command:

$ sudo grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#'

If the either of the following entries are returned, this is a finding:
ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL"
  desc 'fix', 'Configure the operating system to restrict privilege elevation to authorized personnel.

Remove the following entries from the /etc/sudoers file or any configuration file under /etc/sudoers.d/:

ALL     ALL=(ALL) ALL
ALL     ALL=(ALL:ALL) ALL'
  impact 0.5
  tag check_id: 'C-78962r1101702_chk'
  tag severity: 'medium'
  tag gid: 'V-274861'
  tag rid: 'SV-274861r1101704_rule'
  tag stig_id: 'UBTU-22-654224'
  tag gtitle: 'SRG-OS-000396-GPOS-00176'
  tag fix_id: 'F-78867r1101703_fix'
  tag 'documentable'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']

  bad_patterns = [
    /^ALL\s+ALL=\(ALL\)\s+ALL$/,
    /^ALL\s+ALL=\(ALL:ALL\)\s+ALL$/
  ]

  privilege_elevation = command("grep -h -v '^#' /etc/sudoers /etc/sudoers.d/* 2>/dev/null").stdout.strip.split("\n")

  bad_matches = privilege_elevation.select do |line|
    bad_patterns.any? { |pat| line.match?(pat) }
  end

  describe 'Prohibited sudoers entries' do
    it 'should not be present' do
      expect(bad_matches).to be_empty
    end
  end
end
