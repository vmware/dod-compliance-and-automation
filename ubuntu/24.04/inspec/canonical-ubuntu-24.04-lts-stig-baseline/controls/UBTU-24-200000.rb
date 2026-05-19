control 'UBTU-24-200000' do
  title 'Ubuntu 24.04 LTS must limit the number of concurrent sessions to 10 for all accounts and/or account types.'
  desc 'Ubuntu 24.04 LTS management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to denial-of-service (DoS) attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Verify Ubuntu 24.04 LTS limits the number of concurrent sessions to 10 for all accounts and/or account types with the following command:

$ grep -r maxlogins /etc/security/limits.conf /etc/security/limits.d/*.conf
/etc/security/limits.d/maxlogins.conf:* hard maxlogins 10

If the "maxlogins" item does not have a value of "10" or less, is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to limit the number of concurrent sessions to 10 for all accounts and/or account types.

Add the following line to the top of the /etc/security/limits.conf or in a ".conf" file defined in /etc/security/limits.d/:

* hard maxlogins 10'
  impact 0.3
  tag check_id: 'C-74710r1101773_chk'
  tag severity: 'low'
  tag gid: 'V-270677'
  tag rid: 'SV-270677r1101774_rule'
  tag stig_id: 'UBTU-24-200000'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-74611r1066519_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe limits_conf do
    its('*') { should include ['hard', 'maxlogins', input('maxlogins').to_s] }
  end
end
