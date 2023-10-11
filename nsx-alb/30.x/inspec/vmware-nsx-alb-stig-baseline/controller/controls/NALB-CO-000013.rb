control 'NALB-CO-000013' do
  title 'The NSX Advanced Load Balancer Controller must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the device.'
  desc  "
    Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces with human users.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the access settings to verify if the DoD-approved banner has been configured.

    From the NSX ALB Controller web interface go to Administration >> System Settings >> Access >> Banners.

    If the \"Login Banner\" is not configured with the Standard Mandatory DoD Notice and Consent Banner, this is a finding.
  "
  desc 'fix', "
    To configure the \"Login Banner\", do the following:

    From the NSX ALB Controller web interface go to Administration >> System Settings.

    Click the edit icon next to \"System Settings\".

    Update the \"Login Banner\" field under \"Access\" with the below text and click Save.

    You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    -At any time, the USG may inspect and seize data stored on this IS.
    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential.
    See User Agreement for details.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag gid: 'V-NALB-CO-000013'
  tag rid: 'SV-NALB-CO-000013'
  tag stig_id: 'NALB-CO-000013'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

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
    banner_input = input('dod_banner')
    describe 'The Login Banner' do
      subject { resultsjson['linux_configuration']['banner'] }
      it { should cmp banner_input }
    end
  end
end
