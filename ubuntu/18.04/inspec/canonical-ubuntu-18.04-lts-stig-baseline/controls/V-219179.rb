# encoding: UTF-8

control 'V-219179' do
  title "The Ubuntu operating system must enforce a 60-day maximum password
lifetime restriction. Passwords for new users must have a 60-day maximum
password lifetime restriction."
  desc  "Any password, no matter how complex, can eventually be cracked.
Therefore, passwords need to be changed periodically. If the operating system
does not limit the lifetime of passwords and force users to change their
passwords, there is the risk that the operating system passwords could be
compromised."
  desc  'rationale', ''
  desc  'check', "
    Verify that the Ubuntu operating system enforces a 60-day maximum password
lifetime for new user accounts by running the following command:

    # grep -i pass_max_days /etc/login.defs
    PASS_MAX_DAYS 60

    If the \"PASS_MAX_DAYS\" parameter value is less than 60, or commented out,
this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to enforce a 60-day maximum password
lifetime.

    Add, or modify the following line in the \"/etc/login.defs\" file:

    PASS_MAX_DAYS 60
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000076-GPOS-00044'
  tag gid: 'V-219179'
  tag rid: 'SV-219179r508662_rule'
  tag stig_id: 'UBTU-18-010107'
  tag fix_id: 'F-20903r304866_fix'
  tag cci: ['SV-109689', 'V-100585', 'CCI-000199']
  tag nist: ['IA-5 (1) (d)']

  describe login_defs do
    its('PASS_MAX_DAYS') { should cmp <= 60 }
  end
end

