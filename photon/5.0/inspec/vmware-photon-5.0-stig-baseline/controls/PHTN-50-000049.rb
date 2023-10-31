control 'PHTN-50-000049' do
  title 'The Photon operating system must not have duplicate User IDs (UIDs).'
  desc  'To ensure accountability and prevent unauthenticated access, organizational users must be uniquely identified and authenticated to prevent potential misuse and provide for nonrepudiation.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify there are no duplicate user IDs present:

    # awk -F \":\" 'list[$3]++{print $1, $3}' /etc/passwd

    If any lines are returned, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/passwd

    Configure each user account that has a duplicate UID with a unique UID.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag gid: 'V-PHTN-50-000049'
  tag rid: 'SV-PHTN-50-000049'
  tag stig_id: 'PHTN-50-000049'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  describe command('awk -F ":" \'list[$3]++{print $1, $3}\' /etc/passwd') do
    its('stdout') { should cmp '' }
    its('stderr') { should cmp '' }
  end
end
