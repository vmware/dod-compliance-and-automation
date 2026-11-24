control 'VCFA-9X-000372' do
  title 'VMware Cloud Foundation SDDC Manager must compare internal information system clocks with an authoritative time server.'
  desc  "
    Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity.

    Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).
  "
  desc  'rationale', ''
  desc  'check', "
    From the SDDC Manager appliance command line, run the following to verify NTP is configured to synchronize with approved time servers:

    #  grep -E '^\\s*(server|peer|multicastclient)' /etc/ntp.conf

    The output should be similar to the following where the servers listed are set to approved time sources for the environment:

    server 10.0.0.254
    server time.domain.local

    If the NTP servers listed are not site specific authoritative time sources, this is a finding.
  "
  desc 'fix', "
    To configure NTP on only SDDC Manager, do the following:

    From the SDDC Manager appliance command line, navigate to and open:

    /etc/ntp.conf

    Add/update/remove any \"server\" lines as necessary to configure only authoritative time sources, for example:

    server 10.0.0.254
    server time.domain.local

    Restart the ntpd service by running the following command:

    # systemctl restart ntpd.service

    NTP for SDDC Manager may also be configured through the UI, but doing it in this manner also updates other components and does not necessarily reflect the running configuration, but may only show just what was last configured.

    To configure NTP for SDDC Manager, ESX, vCenter, and NSX, do the following:

    From VCF Operations, go to Administration >> SDDC Manager.

    Select the target VCF instance to configure and go to Network Settings >> NTP Configuration.

    Click \"Edit\".

    On the Overview and Prerequisites panes click \"Next\".

    Enter a comma separated list of authoritative time servers and click \"Save\".

    Note: It is recommended to configure 1 or 3 or more NTP servers to help prevent \"split-brain\" scenarios.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000371'
  tag gid: 'V-VCFA-9X-000372'
  tag rid: 'SV-VCFA-9X-000372'
  tag stig_id: 'VCFA-9X-000372'
  tag cci: ['CCI-004923']
  tag nist: ['SC-45 (1) (a)']

  describe 'This check is manual due to no available API or policy based and must be reviewed manually.' do
    skip 'This check is manual due to no available API or policy based and must be reviewed manually.'
  end
end
