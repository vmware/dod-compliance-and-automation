control 'UBTU-24-200680' do
  title 'Ubuntu 24.04 LTS must be configured to enforce the acknowledgement of the Standard Mandatory DOD Notice and Consent Banner for all SSH connections.'
  desc 'The banner must be acknowledged by the user prior to allowing the user access to Ubuntu 24.04 LTS. This provides assurance that the user has seen the message and accepted the conditions for access. If the consent banner is not acknowledged by the user, DOD will not be in compliance with system use notifications required by law.

Ubuntu 24.04 LTS must prevent further activity until the user executes a positive action to manifest agreement.'
  desc 'check', 'Verify Ubuntu 24.04 LTS is configured to prompt a user to acknowledge the Standard Mandatory DOD Notice and Consent Banner before granting access with the following command:

$ less /etc/profile.d/ssh_confirm.sh
#!/bin/bash

if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
        while true; do
                read -p "


You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

Do you agree? [y/N] " yn
                case $yn in
                        [Yy]* ) break ;;
                        [Nn]* ) exit 1 ;;
                esac
        done
fi

If the output does not match the text above, this is a finding.'
  desc 'fix', 'Configure Ubuntu 24.04 LTS to prompt a user to acknowledge the Standard Mandatory DOD Notice and Consent Banner before granting access:

$ sudo vi /etc/profile.d/ssh_confirm.sh
#!/bin/bash

if [ -n "$SSH_CLIENT" ] || [ -n "$SSH_TTY" ]; then
        while true; do
                read -p "

You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.

By using this IS (which includes any device attached to this IS), you consent to the following conditions:

-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

-At any time, the USG may inspect and seize data stored on this IS.

-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.

Do you agree? [y/N] " yn
                case $yn in
                        [Yy]* ) break ;;
                        [Nn]* ) exit 1 ;;
                esac
        done
fi

Note: The "ssh_confirm.sh" script is provided as a supplemental file to this document.'
  impact 0.5
  tag check_id: 'C-74727r1066569_chk'
  tag severity: 'medium'
  tag gid: 'V-270694'
  tag rid: 'SV-270694r1066571_rule'
  tag stig_id: 'UBTU-24-200680'
  tag gtitle: 'SRG-OS-000024-GPOS-00007'
  tag fix_id: 'F-74628r1066570_fix'
  tag 'documentable'
  tag cci: ['CCI-000050']
  tag nist: ['AC-8 b']

  describe('Verify that the SSH connections is configured to enforce the acknowledgement of the Standard Mandatory DOD Notice and Consent Banner') do
    skip('This is a manual review.')
  end
end
