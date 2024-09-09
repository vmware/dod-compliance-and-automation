control 'NMGR-4X-000014' do
  title 'The NSX Manager must retain the Standard Mandatory DOD Notice and Consent Banner on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access.'
  desc 'The banner must be acknowledged by the administrator prior to the device allowing the administrator access to the network device. This provides assurance that the administrator has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the administrator, DOD will not be in compliance with system use notifications required by law.

To establish acceptance of the network administration policy, a click-through banner at management session logon is required. The device must prevent further activity until the administrator executes a positive action to manifest agreement.

In the case of CLI access using a terminal client, entering the username and password when the banner is presented is considered an explicit action of acknowledgement. Entering the username, viewing the banner, then entering the password is also acceptable.'
  desc 'check', 'From the NSX Manager web interface, go to System >> Settings >> General Settings >> User Interface.

Review the Login Consent Settings.

Verify "Login Consent" is not On.
Verify "Require Explicit User Consent" is set to Yes.

If the Standard Mandatory DOD Notice and Consent Banner is not retained on the screen until the administrator acknowledges the usage conditions and takes explicit actions to log on for further access, this is a finding.'
  desc 'fix', 'From the NSX Manager web interface, go to System >> Settings >> General Settings >> User Interface.

Under Login Consent Settings, click "Edit".

Toggle "Login Consent" to On.

Toggle "Require Explicit User Consent" to Yes.

Note: The banner text is also entered; however, that is covered by NMGR-4X-000013.'
  impact 0.5
  tag check_id: 'C-67106r977383_chk'
  tag severity: 'medium'
  tag gid: 'V-263206'
  tag rid: 'SV-263206r977385_rule'
  tag stig_id: 'NMGR-4X-000014'
  tag gtitle: 'SRG-APP-000069-NDM-000216'
  tag fix_id: 'F-67014r977384_fix'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']

  result = http("https://#{input('nsxManager')}/api/v1/loginbanner",
                method: 'GET',
                headers: {
                  'Accept' => 'application/json',
                  'X-XSRF-TOKEN' => "#{input('sessionToken')}",
                  'Cookie' => "#{input('sessionCookieId')}"
                },
                ssl_verify: false)

  describe result do
    its('status') { should cmp 200 }
  end
  unless result.status != 200
    describe json(content: result.body) do
      its('login_banner_content') { should cmp "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.\n\nBy using this IS (which includes any device attached to this IS), you consent to the following conditions:\n-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.\n-At any time, the USG may inspect and seize data stored on this IS.\n-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.\n-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details." }
      its('login_banner_status') { should cmp 'true' }
    end
  end
end
