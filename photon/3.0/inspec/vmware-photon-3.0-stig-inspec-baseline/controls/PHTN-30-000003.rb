control 'PHTN-30-000003' do
  title 'The Photon operating system must display the Standard Mandatory DoD Notice and Consent Banner before granting SSH access.'
  desc  'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # sshd -T|&grep -i Banner

    Expected result:

    banner /etc/issue

    If the output does not match the expected result, this is a finding.

    Next, open /etc/issue with a text editor.

    If the file does not contain the Standard Mandatory DoD Notice and Consent Banner, this is a finding.

    Standard Mandatory DoD Notice and Consent Banner:

    \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    -At any time, the USG may inspect and seize data stored on this IS.
    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.
    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"
  "
  desc 'fix', "
    Navigate to and open:

    /etc/ssh/sshd_config

    Ensure that the \"Banner\" line is uncommented and set to the following:

    Banner /etc/issue

    Navigate to and open:

    /etc/issue

    Ensure that the file contains the Standard Mandatory DoD Notice and Consent Banner.

    \"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions:
    -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
    -At any time, the USG may inspect and seize data stored on this IS.
    -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG authorized purpose.
    -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
    -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"

    At the command line, execute the following command:

    # systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000023-GPOS-00006'
  tag satisfies: ['SRG-OS-000228-GPOS-00088']
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000003'
  tag cci: ['CCI-000048', 'CCI-001384']
  tag nist: ['AC-8 a', 'AC-8 c 1']

  sshdcommand = input('sshdcommand')
  describe command("#{sshdcommand}|&grep -i Banner") do
    its('stdout.strip') { should cmp 'Banner /etc/issue' }
  end

  describe file('/etc/issue') do
    its('content') { should match /You are accessing a U\.S\. Government/ }
  end
end
