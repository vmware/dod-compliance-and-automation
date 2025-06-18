control 'UBTU-22-412020' do
  title 'Ubuntu 22.04 LTS must limit the number of concurrent sessions to ten for all accounts and/or account types.'
  desc 'Ubuntu 22.04 LTS management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to denial-of-service (DoS) attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS limits the number of concurrent sessions to 10 for all accounts and/or account types by using the following command:

     $ sudo grep -r -s '^[^#].*maxlogins' /etc/security/limits.conf /etc/security/limits.d/*.conf
     /etc/security/limits.conf:* hard maxlogins 10

If "maxlogins" does not have a value of "10" or less, is commented out, or is missing, this is a finding.)
  desc 'fix', 'Configure Ubuntu 22.04 LTS to limit the number of concurrent sessions to 10 for all accounts and/or account types.

Add or modify the following line at the top of the "/etc/security/limits.conf" file:

* hard maxlogins 10'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64281r953467_chk'
  tag severity: 'low'
  tag gid: 'V-260552'
  tag rid: 'SV-260552r958398_rule'
  tag stig_id: 'UBTU-22-412020'
  tag gtitle: 'SRG-OS-000027-GPOS-00008'
  tag fix_id: 'F-64189r953468_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']

  describe limits_conf do
    its('*') { should include ['hard', 'maxlogins', input('maxlogins').to_s] }
  end
end
