control 'UBTU-22-271010' do
  title 'Ubuntu 22.04 LTS must enable the graphical user logon banner to display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.'
  desc %q(Display of a standardized and approved use notification before granting access to Ubuntu 22.04 LTS ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

The banner must be formatted in accordance with applicable DOD policy. Use the following verbiage for operating systems that can accommodate banners of 1300 characters:

"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."

Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:

"I've read (literal ampersand) consent to terms in IS user agreem't.")
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the operating system via a graphical user logon by using the following command:

Note: If no graphical user interface is installed, this requirement is not applicable.

     $ grep -i banner-message-enable /etc/gdm3/greeter.dconf-defaults
     banner-message-enable=true

If the value for "banner-message-enable" is set to "false", the line is commented out, or no value is returned, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the operating system via a graphical user logon.

Add or modify the following line in the "/etc/gdm3/greeter.dconf-defaults" file:

[org/gnome/login-screen]
banner-message-enable=true

Update GDM with the new configuration by using the following commands:

     $ sudo dconf update
     $ sudo systemctl restart gdm3'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64264r953416_chk'
  tag severity: 'medium'
  tag gid: 'V-260535'
  tag rid: 'SV-260535r958390_rule'
  tag stig_id: 'UBTU-22-271010'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag fix_id: 'F-64172r953417_fix'
  tag 'documentable'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

  xorg_status = command('which Xorg').exit_status
  if xorg_status == 0
    describe 'banner-message-enable must be set to true' do
      subject { command('grep banner-message-enable /etc/dconf/db/local.d/*') }
      its('stdout') { should match /(banner-message-enable).+=.+(true)/ }
    end
  else
    impact 0.0
    describe command('which Xorg').exit_status do
      skip("GUI not installed.\nwhich Xorg exit_status: #{command('which Xorg').exit_status}")
    end
  end
end
