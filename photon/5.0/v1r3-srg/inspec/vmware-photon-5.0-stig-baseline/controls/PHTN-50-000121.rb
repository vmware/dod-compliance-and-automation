control 'PHTN-50-000121' do
  title 'The Photon operating system must be configured to synchronize with an authoritative DOD time source.'
  desc  "
    Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

    Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

    Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).
  "
  desc  'rationale', ''
  desc  'check', "
    If ntpd is used to sync time, do the following:

    At the command line, run the following command:

    # grep -E '^\\s*(server|peer|multicastclient)' /etc/ntp.conf

    Confirm the servers and peers or multicastclient (as applicable) are local or an authoritative DOD source.

    If a time source is not set, is not set to an authoritative DOD time source, or is commented out, this is a finding.

    If timesyncd is used to sync time, do the following:

    At the command line, run the following command:

    # grep '^NTP' /etc/systemd/timesyncd.conf

    If a time source is not set, is not set to an authoritative DOD time source, or is commented out, this is a finding.

    If chrony is used to sync time, do the following:

    At the command line, run the following command:

    # grep '^server' /etc/chrony/chrony.conf

    If the parameter \"server\" is not set, is not set to an authoritative DOD time source, or is commented out, this is a finding.
  "
  desc 'fix', "
    If ntpd is used to sync time, do the following:

    Navigate to and open:

    /etc/ntp.conf

    Set its contents to the following:

    tinker panic 0
    restrict default kod nomodify notrap nopeer
    restrict 127.0.0.1
    restrict -6 ::1
    driftfile /var/lib/ntp/drift/ntp.drift
    server <site-specific-time-source-IP>

    Resetart the ntpd service by run the following command:

    # systemctl restart ntp.service

    If timesyncd is used to sync time, do the following:

    Navigate to and open:

    /etc/systemd/timesyncd.conf

    Add or update the NTP lines to only contain authoritative time sources, for example:

    NTP=tick.usno.navy.mil

    Restart the timesyncd service by running the following command:

    systemctl restart systemd-timesyncd.service

    If chrony is used to sync time, do the following:

    Navigate to and open:

    /etc/chrony/chrony.conf

    Add or update the server lines to only contain authoritative time sources, for example:

    server tick.usno.navy.mil iburst maxpoll 16
    server tock.usno.navy.mil iburst maxpoll 16

    Restart the chrony service by running the following command:

    # systemctl restart chrony.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag satisfies: ['SRG-OS-000356-GPOS-00144']
  tag gid: 'V-PHTN-50-000121'
  tag rid: 'SV-PHTN-50-000121'
  tag stig_id: 'PHTN-50-000121'
  tag cci: ['CCI-001891', 'CCI-002046']
  tag nist: ['AU-8 (1) (a)', 'AU-8 (1) (b)']

  ntptype = input('ntptype')
  ntpservers = input('ntpServers')
  ntpserversstr = input('ntpServers').join(' ')

  if ntptype == 'ntpd'
    describe ntp_conf do
      its('server') { should be_in ntpservers }
    end
    describe systemd_service('ntpd') do
      it { should be_installed }
      it { should be_enabled }
      it { should be_running }
    end
  end

  if ntptype == 'timesyncd'
    describe file('/etc/systemd/timesyncd.conf') do
      its('content') { should match /^NTP=#{ntpserversstr}/ }
    end
    describe systemd_service('systemd-timesyncd') do
      it { should be_installed }
      it { should be_enabled }
      it { should be_running }
    end
  end

  if ntptype == 'chrony'
    describe chrony_conf do
      its('server') { should be_in ntpservers }
    end
    describe systemd_service('chrony') do
      it { should be_installed }
      it { should be_enabled }
      it { should be_running }
    end
  end
end
