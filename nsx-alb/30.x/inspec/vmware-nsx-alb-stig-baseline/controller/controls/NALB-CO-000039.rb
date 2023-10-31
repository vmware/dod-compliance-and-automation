control 'NALB-CO-000039' do
  title 'The NSX Advanced Load Balancer Controller must enforce a minimum 15-character password length.'
  desc  "
    Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. Password length is one factor of several that helps to determine strength and how long it takes to crack a password.

    The shorter the password, the lower the number of possible combinations that need to be tested before the password is compromised. Use of more characters in a password helps to exponentially increase the time and/or resources required to compromise the password.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX ALB Controller shell, run the following command:

     > show systemconfiguration | grep minimum_password_length

    Example Result:
    |   minimum_password_length        | 15                                 |

    If the minimum password length is not 15 or greater, this is a finding.
  "
  desc 'fix', "
    From the NSX ALB Controller shell, run the following commands to modify minimum_password_length value:

    > configure systemconfiguration
    > systemconfiguration> portal_configuration
    > systemconfiguration:portal_configuration> minimum_password_length 15
    > systemconfiguration:portal_configuration> exit
    > systemconfiguration> exit
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000164-NDM-000252'
  tag gid: 'V-NALB-CO-000039'
  tag rid: 'SV-NALB-CO-000039'
  tag stig_id: 'NALB-CO-000039'
  tag cci: ['CCI-000205']
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
    describe 'Minimum password length' do
      subject { resultsjson['portal_configuration']['minimum_password_length'] }
      it { should cmp >= 15 }
    end
  end
end
