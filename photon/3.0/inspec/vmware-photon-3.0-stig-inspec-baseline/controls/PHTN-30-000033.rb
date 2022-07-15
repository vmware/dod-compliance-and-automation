control 'PHTN-30-000033' do
  title 'The Photon operating system must not have Duplicate User IDs (UIDs).'
  desc  'To ensure accountability and prevent unauthenticated access, organizational users must be uniquely identified and authenticated to prevent potential misuse and provide for non-repudiation.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

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
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000033'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  describe command('awk -F ":" \'list[$3]++{print $1, $3}\' /etc/passwd') do
    its('stdout') { should eq '' }
  end
end
