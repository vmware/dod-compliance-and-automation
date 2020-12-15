# encoding: UTF-8

control 'V-219186' do
  title "The Ubuntu Operating system must be configured so that when passwords
are changed or new passwords are established, pwquality must be used."
  desc  "Use of a complex password helps to increase the time and resources
required to compromise the password. Password complexity, or strength, is a
measure of the effectiveness of a password in resisting attempts at guessing
and brute-force attacks. \"pwquality\" enforces complex password construction
configuration and has the ability to limit brute-force attacks on the system."
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system has the libpam-pwquality package
installed, by running the following command:

    # dpkg -l libpam-pwquality

    ii libpam-pwquality:amd64 1.4.0-2 amd64 PAM module to check password
strength

    If \"libpam-pwquality\" is not installed, this is a finding.

    Verify the operating system uses \"pwquality\" to enforce the password
complexity rules.

    Verify the pwquality module is being enforced by the Ubuntu Operating
System, by running the following command:

    # grep -i enforcing /etc/security/pwquality.conf

    enforcing = 1

    If the value of \"enforcing\" is not 1 or the line is commented out, this
is a finding.

    Check for the use of \"pwquality\" with the following command:

    # sudo cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality

    password requisite pam_pwquality.so retry=3 enforce_for_root

    If no output is returned or the line is commented out, this is a finding.
    If the value of \"retry\" is set to \"0\" or greater than \"3\", this is a
finding.
    If \"enforce_for_root\" is missing from the configuration line, this is a
finding.
  "
  desc  'fix', "
    Configure the operating system to use \"pwquality\" to enforce password
complexity rules.

    Install the pam_pwquality package by using the following command:

    # apt-get install libpam-pwquality -y

    Add the following line to \"/etc/security/pwquality.conf\" (or modify the
line to have the required value):

    enforcing = 1

    Add the following line to \"/etc/pam.d/common-password\" (or modify the
line to have the required value):

    password requisite pam_pwquality.so retry=3 enforce_for_root

    Note: The value of \"retry\" should be between \"1\" and \"3\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00225'
  tag gid: 'V-219186'
  tag rid: 'SV-219186r508662_rule'
  tag stig_id: 'UBTU-18-010116'
  tag fix_id: 'F-20910r485729_fix'
  tag cci: ['V-100599', 'SV-109703', 'CCI-000366']
  tag nist: ['CM-6 b']

  describe package('libpam-pwquality') do
    it { should be_installed }
  end

  describe file('/etc/security/pwquality.conf') do
    its('content') { should match '^enforcing\s+=\s+1$' }
  end

  describe file('/etc/pam.d/common-password') do
    its('content') { should match '^password\s+requisite\s+pam_pwquality.so\s+retry=3\s+enforce_for_root$' }
  end
end

