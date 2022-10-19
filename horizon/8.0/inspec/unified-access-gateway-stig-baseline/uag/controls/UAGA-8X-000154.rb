control 'UAGA-8X-000154' do
  title 'The UAG end user interface must display the Standard Mandatory DoD-approved Notice and Consent Banner before granting access to the network.'
  desc  "
    Application servers are required to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system, providing privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance that states that:

    (i) users are accessing a U.S. Government information system;
    (ii) system usage may be monitored, recorded, and subject to audit;
    (iii) unauthorized use of the system is prohibited and subject to criminal and civil penalties; and
    (iv) the use of the system indicates consent to monitoring and recording.

    System use notification messages can be implemented in the form of warning banners displayed when individuals log on to the information system.

    System use notification is intended only for information system access including an interactive logon interface with a human user, and is not required when an interactive interface does not exist.

    Use this banner for desktops, laptops, and other devices accommodating banners of 1300 characters. The banner shall be implemented as a click-through banner at logon (to the extent permitted by the operating system), meaning it prevents further activity on the information system unless and until the user executes a positive action to manifest agreement by clicking on a box indicating \"OK\".

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
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\" >> Click the gear icon for \"Horizon Settings\" >> Click \"More\" to expand the settings.

    If the \"Disclaimer Text\" field does not contain the Standard Mandatory DoD Notice and Consent Banner text, this is a finding.
  "
  desc 'fix', "
    Login to the UAG administrative interface as an administrator.

    Select \"Configure Manually\".

    Navigate to General Settings >> Edge Service Settings >> Toggle the icon to \"Show\" >> Click the gear icon for \"Horizon Settings\" >> Click \"More\" to expand the settings.

    In the \"Disclaimer Text\" field, supply the Standard Mandatory DoD Notice and Consent Banner text:

    \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
    By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    -At any time, the USG may inspect and seize data stored on this IS.
    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-NET-000041-ALG-000022'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'UAGA-8X-000154'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

  result = uaghelper.runrestcommand('rest/v1/config/edgeservice')

  describe result do
    its('status') { should cmp 200 }
  end

  unless result.status != 200
    jsoncontent = json(content: result.body)
    svclist = jsoncontent['edgeServiceSettingsList']

    compareVal = input('warningBanner').gsub(/\s/, '')

    svclist.each do |svc|
      next unless svc['identifier'] == 'VIEW'
      if !svc['disclaimerText'].nil?
        describe 'Checking Warning Banner configuration on end user interface' do
          subject { svc['disclaimerText'].gsub!(/\s/, '') }
          it { should cmp compareVal }
        end
      else
        describe svc['disclaimerText'] do
          it { should_not cmp nil }
        end
      end
    end
  end
end
