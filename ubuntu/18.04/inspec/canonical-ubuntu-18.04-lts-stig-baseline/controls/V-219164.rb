# encoding: UTF-8

control 'V-219164' do
  title "The Ubuntu operating system must enforce a delay of at least 4 seconds
between logon prompts following a failed logon attempt."
  desc  "Limiting the number of logon attempts over a certain time interval
reduces the chances that an unauthorized user may gain access to an account."
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system enforces a delay of at least 4 seconds
between logon prompts following a failed logon attempt.

    Check that the Ubuntu operating system enforces a delay of at least 4
seconds between logon prompts with the following command:

    # grep pam_faildelay /etc/pam.d/common-auth

    auth required pam_faildelay.so delay=4000000

    If the line is not present, or is commented out, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to enforce a delay of at least 4
seconds between logon prompts following a failed logon attempt.

    Edit the file \"/etc/pam.d/common-auth\" and set the parameter
\"pam_faildelay\" to a value of 4000000 or greater:

    auth required pam_faildelay.so delay=4000000
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag gid: 'V-219164'
  tag rid: 'SV-219164r508662_rule'
  tag stig_id: 'UBTU-18-010031'
  tag fix_id: 'F-20888r304821_fix'
  tag cci: ['SV-109659', 'V-100555', 'CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/common-auth') do
    it { should exist }
  end

  describe command('grep pam_faildelay /etc/pam.d/common-auth') do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match /^\s*auth\s+required\s+pam_faildelay.so\s+.*delay=([4-9][\d]{6,}|[1-9][\d]{7,}).*$/ }
  end

  file('/etc/pam.d/common-auth').content.to_s.scan(/^\s*auth\s+required\s+pam_faildelay.so\s+.*delay=(\d+).*$/).flatten.each do |entry|
    describe entry do
      it { should cmp >= 4_000_000 }
    end
  end
end

