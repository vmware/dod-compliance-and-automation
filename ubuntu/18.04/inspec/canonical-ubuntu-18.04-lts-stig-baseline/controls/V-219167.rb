control 'V-219167' do
  title "The Ubuntu operating system must display the Standard Mandatory DoD
Notice and Consent Banner before granting local access to the system via a
graphical user logon."
  desc  "The banner must be acknowledged by the user prior to allowing the user
access to the operating system. This provides assurance that the user has seen
the message and accepted the conditions for access. If the consent banner is
not acknowledged by the user, DoD will not be in compliance with system use
notifications required by law.

    To establish acceptance of the application usage policy, a click-through
banner at system logon is required. The system must prevent further activity
until the user executes a positive action to manifest agreement by clicking on
a box indicating \"OK\".
  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system displays the Standard Mandatory DoD
Notice and Consent Banner before granting access to the operating system via a
graphical user logon.
    Note: If the system does not have Graphical User Interface installed, this
requirement is Not Applicable.

    Check that the operating system displays the exact approved Standard
Mandatory DoD Notice and Consent Banner text with the command:

    # grep banner-message-enable /etc/gdm3/greeter.dconf-defaults

    banner-message-enable=true

    If the line is commented out or set to \"false\", this is a finding.

    # grep banner-message-text /etc/gdm3/greeter.dconf-defaults

    banner-message-text=\"You are accessing a U.S. Government \\(USG\\)
Information System \\(IS\\) that is provided for USG-authorized use only.\\s+By
using this IS \\(which includes any device attached to this IS\\), you consent
to the following conditions:\\s+-The USG routinely intercepts and monitors
communications on this IS for purposes including, but not limited to,
penetration testing, COMSEC monitoring, network operations and defense,
personnel misconduct \\(PM\\), law enforcement \\(LE\\), and
counterintelligence \\(CI\\) investigations.\\s+-At any time, the USG may
inspect and seize data stored on this IS.\\s+-Communications using, or data
stored on, this IS are not private, are subject to routine monitoring,
interception, and search, and may be disclosed or used for any USG-authorized
purpose.\\s+-This IS includes security measures \\(e.g., authentication and
access controls\\) to protect USG interests--not for your personal benefit or
privacy.\\s+-Notwithstanding the above, using this IS does not constitute
consent to PM, LE or CI investigative searching or monitoring of the content of
privileged communications, or work product, related to personal representation
or services by attorneys, psychotherapists, or clergy, and their assistants.
Such communications and work product are private and confidential. See User
Agreement for details.\"

    If the banner-message-text is missing, commented out, or the text does not
match the Standard Mandatory DoD Notice and Consent Banner exactly, this is a
finding.
  "
  desc 'fix', "
    Edit the /etc/gdm3/greeter.dconf-defaults file.

    Uncomment (remove the leading '#' characters) the following 3 configuration
lines:

    [org/gnome/login-screen]

    banner-message-enable=true
    banner-message-text='Welcome'

    Note: the lines are all near the bottom of the file but they are not
adjacent to each other.

    Edit the banner-message-text='Welcome' line to contain the appropriate
banner message text as shown below:

    banner-message-text='You are accessing a U.S. Government (USG) Information
System (IS) that is provided for USG-authorized use only.\
    \
    By using this IS (which includes any device attached to this IS), you
consent to the following conditions:\
    \
    -The USG routinely intercepts and monitors communications on this IS for
purposes including, but not limited to, penetration testing, COMSEC monitoring,
network operations and defense, personnel misconduct (PM), law enforcement
(LE), and counterintelligence (CI) investigations.\
    \
    -At any time, the USG may inspect and seize data stored on this IS.\
    \
    -Communications using, or data stored on, this IS are not private, are
subject to routine monitoring, interception, and search, and may be disclosed
or used for any USG-authorized purpose.\
    \
    -This IS includes security measures (e.g., authentication and access
controls) to protect USG interests--not for your personal benefit or privacy.\
    \
    -Notwithstanding the above, using this IS does not constitute consent to
PM, LE or CI investigative searching or monitoring of the content of privileged
communications, or work product, related to personal representation or services
by attorneys, psychotherapists, or clergy, and their assistants. Such
communications and work product are private and confidential. See User
Agreement for details.'

    Note that it is similar to the text in /etc/issue but it is all on a single
line and the newline characters have been replaced with \
    .

    # sudo dconf update
    # sudo systemctl restart gdm3
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000024-GPOS-00007'
  tag gid: 'V-219167'
  tag rid: 'SV-219167r508662_rule'
  tag stig_id: 'UBTU-18-010035'
  tag fix_id: 'F-20891r304830_fix'
  tag cci: %w[V-100561 SV-109665 CCI-000050]
  tag nist: ['AC-8 b']

  gnome_installed = (package('ubuntu-gnome-desktop').installed? || package('ubuntu-desktop').installed? || package('gdm3').installed?)
  if !gnome_installed
    describe 'The GUI is installed on the system' do
      subject { gnome_installed }
      it { should be false }
    end
  else
    describe command('/usr/lib/update-notifier/apt-check --human-readable') do
      its('exit_status') { should cmp 0 }
      its('stdout') { should match '^0 updates are security updates.$' }
    end

    describe 'banner-message-enable must be set to true' do
      subject { command('grep banner-message-enable /etc/dconf/db/local.d/*') }
      its('stdout') { should match(/(banner-message-enable).+=.+(true)/) }
    end
  end
end
