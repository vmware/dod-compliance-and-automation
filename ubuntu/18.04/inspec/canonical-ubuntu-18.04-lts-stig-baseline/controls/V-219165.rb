# encoding: UTF-8

control 'V-219165' do
  title "The Ubuntu operating system must display the date and time of the last
successful account logon upon logon."
  desc  "Configuring the Ubuntu operating system to implement organization-wide
security implementation guides and security checklists ensures compliance with
federal standards and establishes a common security baseline across DoD that
reflects the most restrictive security posture consistent with operational
requirements.

    Configuration settings are the set of parameters that can be changed in
hardware, software, or firmware components of the system that affect the
security posture and/or functionality of the system. Security-related
parameters are those parameters impacting the security state of the system,
including the parameters required to satisfy other security control
requirements. Security-related parameters include, for example: registry
settings; account, file, directory permission settings; and settings for
functions, ports, protocols, services, and remote connections.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify users are provided with feedback on when account accesses last
occurred.

    Check that \"pam_lastlog\" is used and not silent with the following
command:

    # grep pam_lastlog /etc/pam.d/login

    session required pam_lastlog.so showfailed

    If \"pam_lastlog\" is missing from \"/etc/pam.d/login\" file, is not
\"required\", or the \"silent\" option is present, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to provide users with feedback on
when account accesses last occurred by setting the required configuration
options in \"/etc/pam.d/postlogin-ac\".

    Add the following line to the top of \"/etc/pam.d/login\":

    session required pam_lastlog.so showfailed
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag gid: 'V-219165'
  tag rid: 'SV-219165r508662_rule'
  tag stig_id: 'UBTU-18-010032'
  tag fix_id: 'F-20889r304824_fix'
  tag cci: ['V-100557', 'SV-109661', 'CCI-000366']
  tag nist: ['CM-6 b']

  describe file('/etc/pam.d/login') do
    it { should exist }
  end

  describe command('grep pam_lastlog /etc/pam.d/login') do
    its('exit_status') { should eq 0 }
    its('stdout.strip') { should match /^\s*session\s+required\s+pam_lastlog.so/ }
    its('stdout.strip') { should_not match /^\s*session\s+required\s+pam_lastlog.so[\s\w\d\=]+.*silent/ }
  end
end

