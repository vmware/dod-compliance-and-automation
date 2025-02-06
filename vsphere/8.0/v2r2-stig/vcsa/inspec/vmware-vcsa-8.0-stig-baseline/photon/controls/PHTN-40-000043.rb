control 'PHTN-40-000043' do
  title 'The Photon operating system must prohibit password reuse for a minimum of five generations.'
  desc 'Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. If the information system or application allows the user to consecutively reuse their password when that password has exceeded its defined lifetime, the end result is a password that is not changed as per policy requirements.'
  desc 'check', %q(At the command line, run the following commands to verify passwords are not reused for a minimum of five generations:

# grep '^password.*pam_pwhistory.so' /etc/pam.d/system-password

Example result:

password required pam_pwhistory.so remember=5 retry=3 enforce_for_root use_authtok

If the "remember" option is not set to "5" or greater, this is a finding.)
  desc 'fix', 'Navigate to and open:

/etc/pam.d/system-password

Configure the pam_pwhistory.so line to have the "remember" option set to 5 or greater as follows:

password required pam_pwhistory.so remember=5 retry=3 enforce_for_root use_authtok

Note: On vCenter appliances, the equivalent file must be edited under "/etc/applmgmt/appliance", if one exists, for the changes to persist after a reboot.'
  impact 0.5
  tag check_id: 'C-62562r933525_chk'
  tag severity: 'medium'
  tag gid: 'V-258822'
  tag rid: 'SV-258822r1003637_rule'
  tag stig_id: 'PHTN-40-000043'
  tag gtitle: 'SRG-OS-000077-GPOS-00045'
  tag fix_id: 'F-62471r933526_fix'
  tag cci: ['CCI-004061']
  tag nist: ['IA-5 (1) (b)']

  if input('useHistoryConf')
    describe parse_config_file('/etc/security/pwhistory.conf') do
      its('remember') { should cmp >= 5 }
    end
  else
    describe file('/etc/pam.d/system-password') do
      its('content') { should match /^password\s+(required|requisite)\s+pam_pwhistory\.so\s+(?=.*\bremember=5\b).*$/ }
    end
  end
end
