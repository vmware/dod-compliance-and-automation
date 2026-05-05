control 'VCFN-9X-000041' do
  title 'The VMware Cloud Foundation NSX Manager must enforce password complexity by requiring that at least one numeric character be used for local accounts.'
  desc  "
    Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

    Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.
  "
  desc  'rationale', ''
  desc  'check', "
    From an NSX Manager shell, run the following NSX CLI command:

    >  get password-complexity

    If the minimum numeric characters is not 1 or more, this is a finding.

    Note: If a maximum number of numeric characters has been configured a minimum will not be shown.
  "
  desc 'fix', "
    From an NSX Manager shell, run the following NSX CLI command:

    > set password-complexity digits -1

    Note: Negative numbers indicate a minimum number of characters.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000168-NDM-000256'
  tag gid: 'V-VCFN-9X-000041'
  tag rid: 'SV-VCFN-9X-000041'
  tag stig_id: 'VCFN-9X-000041'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  result = http("https://#{input('nsx_managerAddress')}/api/v1/node/aaa/auth-policy",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('digits') { should cmp <= -1 }
    end
  end
end
