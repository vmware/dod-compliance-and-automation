# encoding: UTF-8

control 'V-219194' do
  title "The Ubuntu operating system must configure /var/log/syslog file with
mode 0640 or less permissive."
  desc  "Only authorized personnel should be aware of errors and the details of
the errors. Error messages are an indicator of an organization's operational
state or can identify the operating system or platform. Additionally,
Personally Identifiable Information (PII) and operational information must not
be revealed through error messages to unauthorized personnel or their
designated representatives.

    The structure and content of error messages must be carefully considered by
the organization and development team. The extent to which the information
system is able to identify and handle error conditions is guided by
organizational policy and operational requirements.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that the Ubuntu operating system configures the /var/log/syslog file
with mode 0640 or less permissive.

    Check the /var/log/syslog permissions by running the following command:

    # stat -c \"%n %a\" /var/log/syslog

    /var/log/syslog 640

    If a value of \"640\" or less permissive is not returned, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to have permissions of 0640 o for the
/var/log/syslog file by running the following command:

    # sudo chmod 0640 /var/log/syslog
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-219194'
  tag rid: 'SV-219194r508662_rule'
  tag stig_id: 'UBTU-18-010127'
  tag fix_id: 'F-20918r304911_fix'
  tag cci: ['SV-109719', 'V-100615', 'CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/var/log/syslog') do
    it { should_not be_more_permissive_than('0640') }
  end
end

