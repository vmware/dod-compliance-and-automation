control 'VCFN-9X-000013' do
  title 'The VMware Cloud Foundation NSX Manager must display the Standard Mandatory DoD Notice and Consent Banner before granting access.'
  desc  "
    Display of the DoD-approved use notification before granting access to the network device ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces with human users.
  "
  desc  'rationale', ''
  desc  'check', "
    From the NSX Manager web interface, go to System >> Settings >> General Settings >> User Interface.

    Review the Login Consent Settings.

    If \"Login Consent\" is not On, this is a finding.

    If \"Require Explicit User Consent\" is not Yes, this is a finding.

    If the \"Consent Message Description\" does not contain the Standard Mandatory DOD Notice and Consent Banner verbiage, this is a finding.

    The Standard Mandatory DOD Notice and Consent Banner verbiage is as follows:

    \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    -At any time, the USG may inspect and seize data stored on this IS.
    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"
  "
  desc 'fix', "
    From the NSX Manager web interface, go to System >> Settings >> General Settings >> User Interface.

    Under Login Consent Settings click Edit.

    Toggle \"Login Consent\" to On.

    Toggle \"Require Explicit User Consent\" to Yes.

    Enter a \"Consent Message Title\" such as \"Standard Mandatory DOD Notice and Consent Banner\".

    Enter the banner language in the \"Consent Message Description\" text box and click Save.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000068-NDM-000215'
  tag satisfies: ['SRG-APP-000069-NDM-000216']
  tag gid: 'V-VCFN-9X-000013'
  tag rid: 'SV-VCFN-9X-000013'
  tag stig_id: 'VCFN-9X-000013'
  tag cci: ['CCI-000048', 'CCI-000050']
  tag nist: ['AC-8 a', 'AC-8 b']

  result = http("https://#{input('nsx_managerAddress')}/api/v1/loginbanner",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('nsx_sessionToken')}",
                  'Cookie' => "#{input('nsx_sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('login_banner_content') { should cmp "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." }
      its('login_banner_checkbox_flag') { should cmp 'true' }
      its('login_banner_status') { should cmp 'true' }
    end
  end
end
