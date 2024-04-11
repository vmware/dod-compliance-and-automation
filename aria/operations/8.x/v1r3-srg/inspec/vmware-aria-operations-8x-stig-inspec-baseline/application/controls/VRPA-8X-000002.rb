control 'VRPA-8X-000002' do
  title 'VMware Aria Operations must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.'
  desc  "
    Application servers are required to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system management interface, providing privacy and security notices consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance that states that:

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
    Login to vRealize Operations Manager to check if the DoD banner is displayed.

    If users are not presented with the DoD Notice and Consent Banner before login, this is a finding.
  "
  desc  'fix', "
    The banner can be displayed in several ways for vRealize Operations Manager by using either vSphere SSO or VMware Identity Manager as an authentication source and then configuring those sources appropriately, or within vRealize Operations Manager directly.

    To configure authentication sources in vRealize Operations Manager perform the following:

    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Authentication Sources.

    Click Add and choose either SSO SAML or VMware Identity Manager as the source type.

    Fill in the environment specific details and compete the configuration.

    The authentication source must be then appropriately configured to support the DoD banner.  For vCenter refer to the vCenter STIG and for vIDM refer to the accompanying white paper.

    To configure the login banner within vRealize Operations Manager perform the following:

    Login to the vRealize Operations Manager portal as an administrator.

    Navigate to Administration >> Global Settings >> User Access.

    Ensure the \"Login Message\" toggle is set to \"Activated\", then under \"Display Content\" ensure the login banner information is entered correctly.

    Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000068-AS-000035'
  tag gid: 'V-VRPA-8X-000002'
  tag rid: 'SV-VRPA-8X-000002'
  tag stig_id: 'VRPA-8X-000002'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
