control 'NMGR-4X-000044' do
  title 'The NSX Manager must require that when a password is changed, the characters are changed in at least eight of the positions within the password.'
  desc 'If the application allows the user to consecutively reuse extensive portions of passwords, this increases the chances of password compromise by increasing the window of opportunity for attempts at guessing and brute-force attacks.

The number of changed characters refers to the number of changes required with respect to the total number of positions in the current password. In other words, characters may be the same within the two passwords; however, the positions of the like characters must be different.

Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.'
  desc 'check', 'From an NSX Manager shell, run the following command:

>  get password-complexity

If the number of consecutive characters allowed for reuse is not eight or more, this is a finding.

Note: If this has not previously been configured it will not be shown in the output.'
  desc 'fix', 'From an NSX Manager shell, run the following command:

> set password-complexity max-repeats 8'
  impact 0.5
  ref 'DPMS Target VMware NSX 4.x Manager NDM'
  tag check_id: 'C-69238r994184_chk'
  tag severity: 'medium'
  tag gid: 'V-265321'
  tag rid: 'SV-265321r1043189_rule'
  tag stig_id: 'NMGR-4X-000044'
  tag gtitle: 'SRG-APP-000170-NDM-000329'
  tag fix_id: 'F-69146r994185_fix'
  tag 'documentable'
  tag cci: ['CCI-000195']
  tag nist: ['IA-5 (1) (b)']

  result = http("https://#{input('nsxManager')}/api/v1/node/aaa/auth-policy",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('max_repeats') { should cmp >= 8 }
    end
  end
end
