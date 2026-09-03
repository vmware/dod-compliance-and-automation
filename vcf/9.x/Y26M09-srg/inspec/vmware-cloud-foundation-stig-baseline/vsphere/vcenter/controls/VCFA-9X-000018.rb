control 'VCFA-9X-000018' do
  title 'The VMware Cloud Foundation vCenter Server must display the Standard Mandatory DOD Notice and Consent Banner before logon.'
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
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Login Message.

    Review the login message configuration.

    If the selection box next to \"Show login message\" is disabled, \"Details of login message\" is not configured to the standard DOD User Agreement, or the \"Consent checkbox\" is disabled, this is a finding.

    Note: Refer to vulnerability discussion for user agreement language.
  "
  desc 'fix', "
    From the vSphere Client, go to Administration >> Single Sign On >> Configuration >> Login Message.

    Click \"Edit\".

    Click the \"Show login message\" slider to enable.

    Configure the \"Login message\" to \"DOD User Agreement\".

    Click the \"Consent checkbox\" slider to enable.

    Set the \"Details of login message\" to the Standard Mandatory DOD Notice and Consent Banner text.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000068'
  tag satisfies: ['SRG-APP-000069', 'SRG-APP-000070']
  tag gid: 'V-VCFA-9X-000018'
  tag rid: 'SV-VCFA-9X-000018'
  tag stig_id: 'VCFA-9X-000018'
  tag cci: ['CCI-000048', 'CCI-000050', 'CCI-001384', 'CCI-001385', 'CCI-001386', 'CCI-001387', 'CCI-001388']
  tag nist: ['AC-8 a', 'AC-8 b', 'AC-8 c 1', 'AC-8 c 2', 'AC-8 c 3']

  describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
    skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
  end
end
