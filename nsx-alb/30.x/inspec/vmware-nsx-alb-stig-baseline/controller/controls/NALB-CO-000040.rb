control 'NALB-CO-000040' do
  title 'The NSX Advanced Load Balancer Controller must enforce password complexity requirements.'
  desc  "
    Use of a complex passwords helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

    Password complexity is one factor of several that determine how long it takes to crack a password. The more complex the password is, the greater the number of possible combinations that need to be tested before the password is compromised.

    Multifactor authentication (MFA) is required for all administrative and user accounts on network devices, except for an account of last resort and (where applicable) a root account. Passwords should only be used when MFA using PKI is not available, and for the account of last resort and root account.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX ALB Controller shell, run the following command:

    > show systemconfiguration | grep password_strength_check

    Expected result:
    |   password_strength_check        | True

    If \"password_strength_check\" is not set to True, this is a finding.
  "
  desc 'fix', "
    From the NSX ALB Controller shell, run the following commands to enable password_strength_check:

    > configure systemconfiguration
    > systemconfiguration> portal_configuration
    > systemconfiguration:portal_configuration> password_strength_check
    > systemconfiguration:portal_configuration> exit
    > systemconfiguration> exit
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000166-NDM-000254'
  tag satisfies: ['SRG-APP-000167-NDM-000255', 'SRG-APP-000168-NDM-000256', 'SRG-APP-000169-NDM-000257']
  tag gid: 'V-NALB-CO-000040'
  tag rid: 'SV-NALB-CO-000040'
  tag stig_id: 'NALB-CO-000040'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-001619']
  tag nist: ['IA-5 (1) (a)']

  results = http("https://#{input('avicontroller')}/api/systemconfiguration",
                  method: 'GET',
                  headers: {
                    'Accept-Encoding' => 'application/json',
                    'X-Avi-Version' => "#{input('aviversion')}",
                    'Cookie' => "sessionid=#{input('sessionCookieId')}",
                  },
                  ssl_verify: false)

  describe results do
    its('status') { should cmp 200 }
  end

  unless results.status != 200
    resultsjson = JSON.parse(results.body)
    describe 'Password strength check' do
      subject { resultsjson['portal_configuration']['password_strength_check'] }
      it { should cmp true }
    end
  end
end
