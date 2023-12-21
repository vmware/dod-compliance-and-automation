control 'VLIA-8X-000001' do
  title 'VMware Aria Operations for Logs must display the standard DoD notice and consent banner before granting access to the system.'
  desc  "
    Display of the DoD-approved use notification before granting access to the application ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for applications that can accommodate banners of 1300 characters:

    \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"
  "
  desc  'rationale', ''
  desc  'check', "
    Login to VMware Aria Operations for Logs as an administrator to verify that it is configured to show the logon consent banner.

    In the slide-out menu on the left, choose Configuration >> General.

    Under the \"SECURITY TECHNICAL IMPLEMENTATION GUIDE\" section, verify that the \"DoD Consent Agreement\" toggle is enabled.

    Verify that \"Login Message Type\" is set to \"Consent Dialog\", and that the \"Consent Description\" field contains the Standard Mandatory DoD Notice and Consent Banner text.

    If the \"DoD Consent Agreement\" toggle is not enabled, or the \"Consent Description\" field does not contain the Standard Mandatory DoD Notice and Consent Banner text, this is a finding.
  "
  desc 'fix', "
    Login to VMware Aria Operations for Logs as an administrator.

    In the slide-out menu on the left, choose Configuration >> General.

    Under the \"SECURITY TECHNICAL IMPLEMENTATION GUIDE\" section, ensure that the \"DoD Consent Agreement\" toggle is enabled.

    Ensure that the \"Login Message Type\" is set to \"Consent Dialog\".

    In the \"Consent Description\" field, supply the Standard Mandatory DoD Notice and Consent Banner text.

    \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
    By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    -At any time, the USG may inspect and seize data stored on this IS.
    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"

    Click \"Save\".
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000068-AU-000035'
  tag satisfies: ['SRG-APP-000069-AU-000420']
  tag gid: 'V-VLIA-8X-000001'
  tag rid: 'SV-VLIA-8X-000001'
  tag stig_id: 'VLIA-8X-000001'
  tag cci: %w(CCI-000048 CCI-000050)
  tag nist: ['AC-8 a', 'AC-8 b']
  tag mitigations: 'sshd can be configured with a banner but not the UI. We have a prioritized feature request to implement this in the near term.'

  token = http("https://#{input('apipath')}/sessions",
      method: 'POST',
      headers: {
      'Content-Type' => 'application/json',
      'Accept' => 'application/json',
      },
      data: "{\"username\":\"#{input('username')}\",\"password\":\"#{input('password')}\",\"provider\":\"Local\"}",
      ssl_verify: false)

  describe token do
    its('status') { should cmp 200 }
  end

  unless token.status != 200
    sessID = JSON.parse(token.body)['sessionId']

    response = http("https://#{input('apipath')}/dod",
      method: 'GET',
      headers: {
      'Content-Type' => 'application/json',
      'Accept' => 'application/json',
      'Authorization' => "Bearer #{sessID}",
      },
      ssl_verify: false)

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      compareVal = input('loginbanner')

      describe json(content: response.body) do
        its(['enabled']) { should cmp 'true' }
        its(['loginMessageType']) { should cmp 'CONSENT_DIALOG' }
      end
      describe 'Logon Banner Text' do
        subject { json(content: response.body)['description'] }
        it { should include compareVal }
      end
    end
  end
end
