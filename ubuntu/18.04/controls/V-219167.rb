control 'V-219167' do
  title "The Ubuntu operating system must display the Standard Mandatory DoD Notice and
    Consent Banner before granting local access to the system via a graphical user logon."
  desc  "Display of a standardized and approved use notification before
    granting access to the Ubuntu operating system ensures privacy and security
    notification verbiage used is consistent with applicable federal laws,
    Executive Orders, directives, policies, regulations, standards, and guidance.

        System use notifications are required only for access via logon interfaces
    with human users and are not required when such human interfaces do not exist.

        The banner must be formatted in accordance with applicable DoD policy. Use
    the following verbiage for Ubuntu operating systems that can accommodate
    banners of 1300 characters:

        \"You are accessing a U.S. Government (USG) Information System (IS) that is
    provided for USG-authorized use only.

        By using this IS (which includes any device attached to this IS), you
    consent to the following conditions:

        -The USG routinely intercepts and monitors communications on this IS for
    purposes including, but not limited to, penetration testing, COMSEC monitoring,
    network operations and defense, personnel misconduct (PM), law enforcement
    (LE), and counterintelligence (CI) investigations.

        -At any time, the USG may inspect and seize data stored on this IS.

        -Communications using, or data stored on, this IS are not private, are
    subject to routine monitoring, interception, and search, and may be disclosed
    or used for any USG-authorized purpose.

        -This IS includes security measures (e.g., authentication and access
    controls) to protect USG interests--not for your personal benefit or privacy.

        -Notwithstanding the above, using this IS does not constitute consent to
    PM, LE or CI investigative searching or monitoring of the content of privileged
    communications, or work product, related to personal representation or services
    by attorneys, psychotherapists, or clergy, and their assistants. Such
    communications and work product are private and confidential. See User
    Agreement for details.\"

        Use the following verbiage for Ubuntu operating systems that have severe
    limitations on the number of characters that can be displayed in the banner:

        \"I've read and consent to terms in IS user agreem't.\"

  "
  impact 0.5
  tag "gtitle": "SRG-OS-000024-GPOS-00007"
  tag "satisfies": nil
  tag "gid": 'V-219167'
  tag "rid": "SV-219167r378523_rule"
  tag "stig_id": "UBTU-18-010035"
  tag "fix_id": "F-20891r304830_fix"
  tag "cci": [ "CCI-000050" ]
  tag "nist": nil
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  desc 'check', "Verify the Ubuntu operating system displays the Standard Mandatory DoD Notice and
    Consent Banner before granting access to the operating system via a graphical user logon.
    Note: If the system does not have Graphical User Interface installed, this requirement
    is Not Applicable.

    Check that the operating system displays the exact approved Standard Mandatory DoD Notice
    and Consent Banner text with the command:

    # grep banner-message-enable /etc/gdm3/greeter.dconf-defaults

    banner-message-enable=true

    If the line is commented out or set to \"false\", this is a finding.

    # grep banner-message-text /etc/gdm3/greeter.dconf-defaults

    banner-message-text=\"You are accessing a U.S. Government \(USG\) Information System
    \(IS\) that is provided for USG-authorized use only.\s+By using this IS \(which includes
    any device attached to this IS\), you consent to the following conditions:\s+-The USG
    routinely intercepts and monitors communications on this IS for purposes including, but
    not limited to, penetration testing, COMSEC monitoring, network operations and defense,
    personnel misconduct \(PM\), law enforcement \(LE\), and counterintelligence \(CI\)
    investigations.\s+-At any time, the USG may inspect and seize data stored on this IS.
    \s+-Communications using, or data stored on, this IS are not private, are subject
    to routine monitoring, interception, and search, and may be disclosed or used for any
    USG-authorized purpose.\s+-This IS includes security measures \(e.g., authentication
    and access controls\) to protect USG interests--not for your personal benefit or privacy.
    \s+-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI
    investigative searching or monitoring of the content of privileged communications, or
    work product, related to personal representation or services by attorneys,
    psychotherapists, or clergy, and their assistants. Such communications and work product
    are private and confidential. See User Agreement for details.\"

    If the banner-message-text is missing, commented out, or the text does not match the
    Standard Mandatory DoD Notice and Consent Banner exactly, this is a finding.
  "
  desc 'fix', "Edit the /etc/gdm3/greeter.dconf-defaults file.

    Uncomment (remove the leading '#' characters) the following 3 configuration lines:

    [org/gnome/login-screen]

    banner-message-enable=true
    banner-message-text='Welcome'

    Note: the lines are all near the bottom of the file but they are not adjacent to each other.

    Edit the banner-message-text='Welcome' line to contain the appropriate banner message text as
    shown below:

    banner-message-text='You are accessing a U.S. Government (USG) Information System (IS)
    that is provided for USG-authorized use only.\n\nBy using this IS (which includes any
    device attached to this IS), you consent to the following conditions:\n\n-The USG
    routinely intercepts and monitors communications on this IS for purposes including,
    but not limited to, penetration testing, COMSEC monitoring, network operations and
    defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI)
    investigations.\n\n-At any time, the USG may inspect and seize data stored on this IS.
    \n\n-Communications using, or data stored on, this IS are not private, are subject to
    routine monitoring, interception, and search, and may be disclosed or used for any
    USG-authorized purpose.\n\n-This IS includes security measures (e.g., authentication and
    access controls) to protect USG interests--not for your personal benefit or privacy.
    \n\n-Notwithstanding the above, using this IS does not constitute consent to PM, LE or
    CI investigative searching or monitoring of the content of privileged communications, or
    work product, related to personal representation or services by attorneys,
    psychotherapists, or clergy, and their assistants. Such communications and work product
    are private and confidential. See User Agreement for details.'

    Note that it is similar to the text in /etc/issue but it is all on a single line and the
    newline characters have been replaced with \n.

    # sudo dconf update
    # sudo systemctl restart gdm3
  "
  describe command('/usr/lib/update-notifier/apt-check --human-readable') do
    its('exit_status') { should cmp 0 }
    its('stdout') { should match '^0 updates are security updates.$' }
  end

  describe 'banner-message-enable must be set to true' do
    subject { command('grep banner-message-enable /etc/dconf/db/local.d/*') }
    its('stdout') { should match /(banner-message-enable).+=.+(true)/ }
  end
end
