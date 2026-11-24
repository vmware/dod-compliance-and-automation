control 'PHTN-50-000074' do
  title 'The Photon operating system must reveal error messages only to authorized users.'
  desc  "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives."
  desc  'rationale', ''
  desc  'check', "
    This is not applicable to the following VCF components: Operations HCX.

    At the command line, run the following command to verify rsyslog generates log files that are not world readable:

    # grep '^\\$umask' /etc/rsyslog.conf

    Example result:

    $umask 0037

    If \"$umask\" is not set to \"0037\" or more restrictive, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/rsyslog.conf

    Add or update the following line:

    $umask 0037

    At the command line, run the following command:

    # systemctl restart rsyslog.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag gid: 'V-PHTN-50-000074'
  tag rid: 'SV-PHTN-50-000074'
  tag stig_id: 'PHTN-50-000074'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe file('/etc/rsyslog.conf') do
    its('content') { should match /^\$umask\s0037$/ }
  end
end
