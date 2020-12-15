# encoding: UTF-8

control 'V-219189' do
  title "The Ubuntu operating system must configure the /var/log directory to
be group-owned by syslog."
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
    Verify the Ubuntu operating system configures the /var/log directory to be
group-owned by syslog.

    Check that the /var/log directory is group owned by syslog with the
following command:

    # sudo stat -c \"%n %G\" /var/log
    /var/log syslog

    If the /var/log directory is not group-owned by syslog, this is a finding.
  "
  desc  'fix', "
    Configure the Ubuntu operating system to have syslog group-own the /var/log
directory by running the following command:

    # sudo chgrp syslog /var/log
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-219189'
  tag rid: 'SV-219189r508662_rule'
  tag stig_id: 'UBTU-18-010122'
  tag fix_id: 'F-20913r304896_fix'
  tag cci: ['V-100605', 'SV-109709', 'CCI-001314']
  tag nist: ['SI-11 b']

  describe directory('/var/log') do
    its('group') { should cmp 'syslog' }
  end
end

