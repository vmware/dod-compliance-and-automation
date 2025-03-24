control 'PHTN-40-000049' do
  title 'The Photon operating system must not have duplicate User IDs (UIDs).'
  desc 'To ensure accountability and prevent unauthenticated access, organizational users must be uniquely identified and authenticated to prevent potential misuse and provide for nonrepudiation.'
  desc 'check', %q(At the command line, run the following command to verify there are no duplicate user IDs present:

# awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If any lines are returned, this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/passwd

Configure each user account that has a duplicate UID with a unique UID.'
  impact 0.5
  tag check_id: 'C-62566r933537_chk'
  tag severity: 'medium'
  tag gid: 'V-258826'
  tag rid: 'SV-258826r958482_rule'
  tag stig_id: 'PHTN-40-000049'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-62475r933538_fix'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  describe command('awk -F ":" \'list[$3]++{print $1, $3}\' /etc/passwd') do
    its('stdout') { should cmp '' }
    its('stderr') { should cmp '' }
  end
end
