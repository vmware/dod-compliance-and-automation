control 'VCFA-9X-000359' do
  title 'VMware Cloud Foundation Operations for Logs must display the Standard Mandatory DOD Notice and Consent Banner before logon.'
  desc  "
    Display of the DOD-approved use notification before granting access to the application ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via login interfaces with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for applications that can accommodate banners of 1300 characters:

    \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"

    Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

    \"I've read (literal ampersand) consent to terms in IS user agreem't.\"
  "
  desc  'rationale', ''
  desc  'check', "
    If VCF Operations for Logs is not deployed, this is not applicable.

    From VCF Operations for Logs, go to Configuration >> General.

    Review the \"DoD Consent Agreement\" configuration.

    If the \"DoD Consent Agreement\" is disabled, this is a finding.

    If the \"Login Message Type\" is not set to \"Consent Dialog\", this is a finding.

    If the \"Consent Description\" is not configured with the Standard Mandatory DOD Notice, this is a finding.

    Note: Refer to vulnerability discussion for user agreement language.
  "
  desc 'fix', "
    From VCF Operations for Logs, go to Configuration >> General.

    Under \"Security Technical Implementation Guide\" click the radio button next to \"DoD Consent Agreement\" to enable it.

    Configure the \"Login Message Type\" type to \"Consent Dialog\".

    Configure the \"Consent Title\" and enter \"DOD Standard and Mandatory Notice\" or other appropriate text.

    Configure the \"Consent Description\" to include the Standard Mandatory DOD Notice text and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000068'
  tag gid: 'V-VCFA-9X-000359'
  tag rid: 'SV-VCFA-9X-000359'
  tag stig_id: 'VCFA-9X-000359'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

  if input('opslogs_deployed')
    response = http("https://#{input('opslogs_apihostname')}/api/v2/dod",
                    method: 'GET',
                    ssl_verify: false,
                    headers: { 'Content-Type' => 'application/json',
                               'Accept' => 'application/json',
                               'Authorization' => "Bearer #{input('opslogs_apitoken')}" })

    describe response do
      its('status') { should cmp 200 }
    end

    unless response.status != 200
      responseval = json(content: response.body)

      if responseval
        if responseval['enabled'] == true
          describe 'Notice and Consent banner' do
            subject { responseval }
            its(['enabled']) { should cmp true }
            its(['loginMessageType']) { should cmp 'CONSENT_DIALOG' }
            its(['description']) { should include input('opslogs_banner') }
          end
        else
          describe 'Notice and Consent banner' do
            subject { responseval }
            its(['enabled']) { should cmp true }
          end
        end
      else
        describe 'Notice and Consent banner' do
          subject { responseval }
          it { should_not be_nil }
        end
      end
    end
  else
    impact 0.0
    describe 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.' do
      skip 'VCF Operations for Logs is not deployed in the target environment. This control is N/A.'
    end
  end
end
