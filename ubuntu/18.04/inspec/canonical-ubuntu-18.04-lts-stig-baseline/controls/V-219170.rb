# encoding: UTF-8

control 'V-219170' do
  title "The Ubuntu operating system must display the Standard Mandatory DoD
Notice and Consent Banner before granting any publically accessible connection
to the system."
  desc  "Display of a standardized and approved use notification before
granting access to the Ubuntu operating system ensures privacy and security
notification verbiage used is consistent with applicable federal laws,
Executive Orders, directives, policies, regulations, standards, and guidance.

    System use notifications are required only for access via logon interfaces
with human users and are not required when such human interfaces do not exist.

    The banner must be formatted in accordance with applicable DoD policy:

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


  "
  desc  'rationale', ''
  desc  'check', "
    Verify the Ubuntu operating system displays the Standard Mandatory DoD
Notice and Consent Banner before granting access to the Ubuntu operating system
via a ssh logon.

    Check that the Ubuntu operating system displays the Standard Mandatory DoD
Notice and Consent Banner before granting access to the Ubuntu operating system
via a ssh logon with the following command:

    # grep -i banner /etc/ssh/sshd_config

    Banner /etc/issue

    The command will return the banner option along with the name of the file
that contains the ssh banner. If the line is commented out, this is a finding.

    Check the specified banner file to check that it matches the Standard
Mandatory DoD Notice and Consent Banner exactly:

    # cat /etc/issue

    “You are accessing a U.S. Government (USG) Information System (IS) that is
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
Agreement for details.”

    If the banner text does not match the Standard Mandatory DoD Notice and
Consent Banner exactly, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to display the Standard Mandatory DoD
Notice and Consent Banner before granting access to the system via SSH logon.

    Edit the SSH daemon configuration \"/etc/ssh/sshd_config\" file. Uncomment
the banner keyword and configure it to point to the file that contains the
correct banner. An example of this configure is below:

    Banner /etc/issue

    Either create the file containing the banner, or replace the text in the
file with the Standard Mandatory DoD Notice and Consent Banner. The DoD
required text is:

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

    In order for the changes to take effect, the SSH daemon must be restarted.

    # sudo systemctl restart sshd.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag satisfies: ['SRG-OS-000228-GPOS-00088', 'SRG-OS-000023-GPOS-00006']
  tag gid: 'V-219170'
  tag rid: 'SV-219170r508662_rule'
  tag stig_id: 'UBTU-18-010038'
  tag fix_id: 'F-20894r304839_fix'
  tag cci: ['V-100567', 'SV-109671', 'CCI-001384', 'CCI-001385', 'CCI-001386',
'CCI-001387', 'CCI-001388', 'CCI-000048']
  tag nist: ['AC-8 c 1', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 3', "AC-8
a"]

  banner_text = input('banner_text')
  banner_files = [sshd_config.banner].flatten

  banner_files.each do |banner_file|
    if banner_file.nil?
      describe 'The SSHD Banner is not set' do
        subject { banner_file.nil? }
        it { should be false }
      end
    end
    if !banner_file.nil? && !banner_file.match(/none/i).nil?
      describe 'The SSHD Banner is disabled' do
        subject { banner_file.match(/none/i).nil? }
        it { should be true }
      end
    end
    if !banner_file.nil? && banner_file.match(/none/i).nil? && !file(banner_file).exist?
      describe 'The SSHD Banner is set, but, the file does not exist' do
        subject { file(banner_file).exist? }
        it { should be true }
      end
    end
    next unless !banner_file.nil? && banner_file.match(/none/i).nil? && file(banner_file).exist?

    describe 'The SSHD Banner is set to the standard banner and has the correct text' do
      clean_banner = banner_text.gsub(/[\r\n\s]/, '')
      subject { file(banner_file).content.gsub(/[\r\n\s]/, '') }
      it { should cmp clean_banner }
    end
  end
end

