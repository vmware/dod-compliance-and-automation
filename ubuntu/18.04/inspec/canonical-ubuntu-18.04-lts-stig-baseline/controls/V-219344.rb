# encoding: UTF-8

control 'V-219344' do
  title "The Ubuntu operating system must be configured so that a file
integrity tool verifies the correct operation of security functions every 30
days."
  desc  "Without verification of the security functions, security functions may
not operate correctly and the failure may go unnoticed. Security function is
defined as the hardware, software, and/or firmware of the information system
responsible for enforcing the system security policy and supporting the
isolation of code and data on which the protection is based. Security
functionality includes, but is not limited to, establishing system accounts,
configuring access authorizations (i.e., permissions, privileges), setting
events to be audited, and setting intrusion detection parameters.

    Notifications provided by information systems include, for example,
electronic alerts to system administrators, messages to local computer
consoles, and/or hardware indications, such as lights.

    This requirement applies to the Ubuntu operating system performing security
function verification/testing and/or systems and environments that require this
functionality.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that Advanced Intrusion Detection Environment (AIDE) performs a
verification of the operation of security functions every 30 days.

    Note: A file integrity tool other than AIDE may be used, but the tool must
be executed at least once per week.

    Check that AIDE is being executed every 30 days or less with the following
command:

    # ls -al /etc/cron.daily/aide

    -rwxr-xr-x 1 root root 26049 Oct 24 2014 /etc/cron.daily/aide

    If the \"/etc/cron.daily/aide\" file does not exist or a cron job is not
configured to run at least every 30 days, this is a finding.
  "
  desc  'fix', "
    The cron file for AIDE is fairly complex as it creates the report. This
file is installed with the aide-common package and the default can be restored
by copying it from another location:

    # sudo cp /usr/share/aide/config/cron.daily/aide /etc/cron.daily/aide
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000446-GPOS-00200'
  tag gid: 'V-219344'
  tag rid: 'SV-219344r508662_rule'
  tag stig_id: 'UBTU-18-010516'
  tag fix_id: 'F-21068r305361_fix'
  tag cci: ['V-100909', 'SV-110013', 'CCI-002699']
  tag nist: ['SI-6 b']

  describe file('/etc/cron.daily/aide') do
    it { should exist }
  end
end

