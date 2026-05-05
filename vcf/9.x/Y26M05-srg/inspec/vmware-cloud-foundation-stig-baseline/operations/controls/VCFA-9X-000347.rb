control 'VCFA-9X-000347' do
  title 'VMware Cloud Foundation Operations must display the Standard Mandatory DOD Notice and Consent Banner before logon.'
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
    From VCF Operations, go to Administration >> Global Settings >> User Access >> Login Message.

    Review the login message configuration.

    If the login message policy content does not contain the standard DOD user agreement language, this is a finding.

    If the login message policy is not activated, this is a finding.

    Note: Refer to vulnerability discussion for the user agreement language.
  "
  desc 'fix', "
    From VCF Operations, go to Administration >> Global Settings >> User Access >> Login Message.

    If the login message policy is not activated, click on the \"Deactivated\" radio button to enable it and click \"Save\".

    Configure the \"Content\" field to the Standard Mandatory DOD Notice and Consent Banner text.

    Configure an appropriate \"Title\" and a \"Button Label\".

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000068'
  tag gid: 'V-VCFA-9X-000347'
  tag rid: 'SV-VCFA-9X-000347'
  tag stig_id: 'VCFA-9X-000347'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

  describe 'This check is either manual due to no available API or is policy based and must be reviewed manually.' do
    skip 'This check is either manual due to no available API or is policy based and must be reviewed manually.'
  end
end
