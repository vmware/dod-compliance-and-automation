control 'PHTN-30-000033' do
  title 'The Photon operating system must not have duplicate User IDs (UIDs).'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be uniquely identified and authenticated to prevent potential misuse and provide for nonrepudiation.'
  desc 'check', %q(At the command line, run the following command:

# awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If any lines are returned, this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/passwd

Configure each user account that has a duplicate UID with a unique UID.'
  impact 0.5
  tag check_id: 'C-60185r887202_chk'
  tag severity: 'medium'
  tag gid: 'V-256510'
  tag rid: 'SV-256510r887204_rule'
  tag stig_id: 'PHTN-30-000033'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-60128r887203_fix'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  describe command('awk -F ":" \'list[$3]++{print $1, $3}\' /etc/passwd') do
    its('stdout') { should eq '' }
  end
end
