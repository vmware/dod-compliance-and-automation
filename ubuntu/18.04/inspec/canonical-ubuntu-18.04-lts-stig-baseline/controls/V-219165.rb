control 'V-219165' do
  title "The Ubuntu operating system must display the date and time of the last successful
    account logon upon logon."
  desc  "Providing users with feedback on when account accesses last occurred
    facilitates user recognition and reporting of unauthorized account use."

  impact 0.3
  tag "gtitle": "SRG-OS-000480-GPOS-00227"
  tag "gid": 'V-219165'
  tag "rid": "SV-219165r388482_rule"
  tag "stig_id": "UBTU-18-010032"
  tag "fix_id": "F-20889r304824_fix"
  tag "cci": [ "CCI-000366" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify users are provided with feedback on when account accesses last
    occurred.

    Check that \"pam_lastlog\" is used and not silent with the following command:

    # grep pam_lastlog /etc/pam.d/login

    session required pam_lastlog.so showfailed

    If \"pam_lastlog\" is missing from \"/etc/pam.d/login\" file, is not \"required\", or
    the \"silent\" option is present, this is a finding.
  "

  desc 'fix', "Configure the Ubuntu operating system to provide users with feedback on when
    account accesses last occurred by setting the required configuration options in
    \"/etc/pam.d/postlogin-ac\".

    Add the following line to the top of \"/etc/pam.d/login\":

    session required pam_lastlog.so showfailed
  "

  describe file('/etc/pam.d/login') do
    it { should exist }
  end

  describe command('grep pam_lastlog /etc/pam.d/login') do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match /^\s*session\s+required\s+pam_lastlog.so/ }
    its('stdout.strip') { should_not match /^\s*session\s+required\s+pam_lastlog.so[\s\w\d\=]+.*silent/ }
  end
end
