control "PHTN-10-000061" do
  title "The Photon operating system must be configured to synchronize with an
approved DoD time source."
  desc  "Inaccurate time stamps make it more difficult to correlate events and
can lead to an inaccurate analysis. Determining the correct time a particular
event occurred on a system is critical when conducting forensic analysis and
investigating system events. Sources outside the configured acceptable
allowance (drift) may be inaccurate.

    Synchronizing internal information system clocks provides uniformity of
time stamps for information systems with multiple system clocks and systems
connected over a network.

    Organizations should consider endpoints that may not have regular access to
the authoritative time server (e.g., mobile, teleworking, and tactical
endpoints)."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-OS-000355-GPOS-00143"
  tag gid: nil
  tag rid: "PHTN-10-000061"
  tag stig_id: "PHTN-10-000061"
  tag cci: "CCI-001891"
  tag nist: ["AU-8 (1) (a)", "Rev_4"]
  desc 'check', "At the command line, execute the following command:

# grep -E '^\\s*(server|peer|multicastclient)' /etc/ntp.conf

Confirm the servers and peers or multicastclient (as applicable) are local or
an authoritative U.S. DoD source.

If no lines are returned or a non-local/non-authoritative time-server is used,
this is a finding.

OR

Navigate to https://<hostname>:5480 to access the Virtual Appliance Management
Inferface (VAMI). Authenticate and navigate to \"Time\". If no appropriate time
server is specified, this is a finding."
  desc 'fix', "Open /etc/ntp.conf with a text editor and set it's contents to the
following:

tinker panic 0
restrict default kod nomodify notrap nopeer
restrict 127.0.0.1
restrict -6 ::1
driftfile /var/lib/ntp/drift/ntp.drift
server <site-specific-time-source-IP>

At the command line, execute the following commands:

# chkconfig ntpd on
# systemctl start ntp

OR

Navigate to https://<hostname>:5480 to access the Virtual Appliance Management
Inferface (VAMI). Authenticate and navigate to \"Time\". Click \"Edit\" in the
top right and configure at least one appropriate NTP server. Click \"OK\"."

  describe ntp_conf do
    its ('server') { should_not eq nil }
  end

  describe ntp_conf do
    its ('server') { should be_in ["#{input('ntpServer1')}","#{input('ntpServer2')}"] }
  end

  describe systemd_service('ntpd') do
    it { should be_installed}
    it { should be_enabled}
    it { should be_running}
  end

end

