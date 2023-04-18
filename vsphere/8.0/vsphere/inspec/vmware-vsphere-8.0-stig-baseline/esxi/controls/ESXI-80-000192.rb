control 'ESXI-80-000192' do
  title 'The ESXi host Secure Shell (SSH) daemon must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system.'
  desc  "
    Display of a standardized and approved use notification before granting access to the host ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable DOD policy. Use the following verbiage for a host that can accommodate banners of 1300 characters:

    \"You are accessing a U.S. Government (USG) VMM (IS) that is provided for USG-authorized use only.

    By using this IS (which includes any device attached to this IS), you consent to the following conditions:

    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.

    -At any time, the USG may inspect and seize data stored on this IS.

    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.

    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.

    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"

    Use the following verbiage for VMMs that have severe limitations on the number of characters that can be displayed in the banner:

    \"I've read (literal ampersand) consent to terms in IS user agreem't.\"
  "
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command:

    # /usr/lib/vmware/openssh/bin/sshd -T | grep banner

    Expected result:

    banner /etc/issue

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    From an ESXi shell, navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"Banner\" line is uncommented and set to the following:

    Banner /etc/issue

    Restart SSH from the UI or run the following command:

    # /etc/init.d/SSH restart
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-VMM-000060'
  tag gid: 'V-ESXI-80-000192'
  tag rid: 'SV-ESXI-80-000192'
  tag stig_id: 'ESXI-80-000192'
  tag cci: ['CCI-000048']
  tag nist: ['AC-8 a']

  describe 'This check is a manual or policy based check and must be reviewed manually.' do
    skip 'This check is a manual or policy based check and must be reviewed manually.'
  end
end
