control 'WOAA-3X-000070' do
  title 'Workspace ONE Access must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system.'
  desc  'Application servers are required to display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system management interface. '
  desc  'rationale', ''
  desc  'check', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Navigate to the \"Identity & Access Management\" tab.

    Click the \"Setup\" button.

    Click the Worker link for each connector that is being configured.

    Click \"Auth Adapters\" then Click \"CertificateAuthAdapter\".

    If \"Enable Consent Form before Authentication\" is not checked, this is a finding.

    If the \"Consent Form Content\" field does not contain the Standard Mandatory DoD Notice and Consent Banner text, this is a finding.
  "
  desc 'fix', "
    Login to the Workspace ONE Access admin console at \"https://<hostname>/SAAS/admin\" using administrative credentials.

    Navigate to the \"Identity & Access Management\" tab.

    Click the \"Setup\" button.

    Click the Worker link for the connector that is being configured.

    Click \"Auth Adapters\" then Click \"CertificateAuthAdapter\".

    Check the box next to \"Enable Consent Form before Authentication\".

    In the \"Consent Form Content\" field, supply the Standard Mandatory DoD Notice and Consent Banner text.

    \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
    By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    -At any time, the USG may inspect and seize data stored on this IS.
    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"

    Click \"Save\".

    Note: The certificate authentication configuration must be completed before this will be display which is covered by a separate control.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000516-AAA-000690'
  tag gid: 'V-WOAA-3X-000070'
  tag rid: 'SV-WOAA-3X-000070'
  tag stig_id: 'WOAA-3X-000070'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This control is a manual audit...skipping...' do
    skip 'This control is a manual audit...skipping...'
  end
end
