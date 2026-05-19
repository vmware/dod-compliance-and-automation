control 'UBTU-24-300017' do
  title 'Ubuntu 24.04 LTS must enforce a delay of at least four seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.

The delay option is set in microseconds.'
  desc 'check', 'Verify Ubuntu 24.04 LTS enforces a delay of at least four seconds between logon prompts following a failed logon attempt with the following command:

$ grep pam_faildelay /etc/pam.d/common-auth
auth    required    pam_faildelay.so    delay=4000000

If the value for "delay" is not set to "4000000" or greater, the line is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to enforce a delay of at least four seconds between logon prompts following a failed logon attempt.

Edit the file "/etc/pam.d/common-auth" and set the parameter "pam_faildelay" to a value of "4000000" or greater:

auth    required    pam_faildelay.so    delay=4000000'
  impact 0.3
  tag check_id: 'C-74739r1067170_chk'
  tag severity: 'low'
  tag gid: 'V-270706'
  tag rid: 'SV-270706r1068361_rule'
  tag stig_id: 'UBTU-24-300017'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-74640r1066606_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  common_auth_file = input('common_auth_file')

  common_auth_file_exists = file(common_auth_file).exist?

  if common_auth_file_exists
    describe command("grep pam_faildelay #{common_auth_file}") do
      its('exit_status') { should eq 0 }
      its('stdout.strip') { should match(/^\s*auth\s+required\s+pam_faildelay.so\s+.*delay=([4-9][\d]{6,}|[1-9][\d]{7,}).*$/) }
    end
    file(common_auth_file).content.to_s.scan(/^\s*auth\s+required\s+pam_faildelay.so\s+.*delay=(\d+).*$/).flatten.each do |entry|
      describe entry do
        it { should cmp >= 4_000_000 }
      end
    end
  else
    describe("#{common_auth_file} exists") do
      subject { common_auth_file_exists }
      it { should be true }
    end
  end
end
