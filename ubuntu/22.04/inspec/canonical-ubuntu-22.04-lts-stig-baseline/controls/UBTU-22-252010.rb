control 'UBTU-22-252010' do
  title 'Ubuntu 22.04 LTS must, for networked systems, compare internal information system clocks at least every 24 hours with a server synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

Note that USNO offers authenticated NTP service to DOD and U.S. Government agencies operating on the NIPR and SIPR networks. Visit https://www.usno.navy.mil/USNO/time/ntp/DOD-customers for more information.'
  desc 'check', 'Verify Ubuntu 22.04 LTS is configured to compare the system clock at least every 24 hours to the authoritative time source by using the following command:

Note: If the system is not networked, this requirement is not applicable.

     $ sudo grep maxpoll -ir /etc/chrony*
     server tick.usno.navy.mil iburst maxpoll 16

If the "maxpoll" option is set to a number greater than 16, the line is commented out, or is missing, this is a finding.

Verify that the "chrony.conf" file is configured to an authoritative DOD time source by using the following command:

     $ sudo grep -ir server /etc/chrony*
     server tick.usno.navy.mil iburst maxpoll 16
     server tock.usno.navy.mil iburst maxpoll 16
     server ntp2.usno.navy.mil iburst maxpoll 16

If "server" is not defined, is not set to an authoritative DOD time source, is commented out, or missing, this is a finding.'
  desc 'fix', 'Configure Ubuntu 22.04 LTS to compare the system clock at least every 24 hours to the authoritative time source.

Add or modify the following line in the "/etc/chrony/chrony.conf" file:

server [source] iburst maxpoll = 16

Restart "chrony.service" for the changes to take effect by using the following command:

     $ sudo systemctl restart chrony.service'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64248r953368_chk'
  tag severity: 'low'
  tag gid: 'V-260519'
  tag rid: 'SV-260519r1038944_rule'
  tag stig_id: 'UBTU-22-252010'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-64156r953369_fix'
  tag 'documentable'
  tag cci: ['CCI-004923', 'CCI-001891']
  tag nist: ['SC-45 (1) (a)', 'AU-8 (1) (a)']

  is_system_networked = input('is_system_networked')
  chrony_conf_file_path = input('chrony_conf_file_path')

  if is_system_networked

    chrony_conf_exists = file(chrony_conf_file_path).exist?

    if chrony_conf_exists
      describe 'time sources' do
        server_entries = command("grep '^server' #{chrony_conf_file_path}").stdout.strip.split("\n").entries

        server_entries.each do |entry|
          describe entry do
            it { should match "^server\s+.*\s+iburst\s+maxpoll\s+16$" }
          end
        end
      end
    else
      describe "#{chrony_conf_file_path} exists" do
        subject { chrony_conf_exists }
        it { should be true }
      end
    end
  else
    impact 0.0
    describe 'This control is Not Applicable as the system is not networked' do
      skip 'This control is Not Applicable as the system is not networked'
    end
  end
end
