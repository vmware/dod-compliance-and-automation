# encoding: UTF-8

control 'V-219331' do
  title "The Ubuntu operating system must, for networked systems, compare
internal information system clocks at least every 24 hours with a server which
is synchronized to one of the redundant United States Naval Observatory (USNO)
time servers, or a time server designated for the appropriate DoD network
(NIPRNet/SIPRNet), and/or the Global Positioning System (GPS)."
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
endpoints).
  "
  desc  'rationale', ''
  desc  'check', "
    If the system is not networked this requirement is Not Applicable.

    The system clock must be configured to compare the system clock at least
every 24 hours to the authoritative time source.

    Check the value of \"maxpoll\" in the \"/etc/chrony/chrony.conf\" file with
the following command:

    # sudo grep maxpoll /etc/chrony/chrony.conf
    server tick.usno.navy.mil iburst maxpoll 17

    If \"maxpoll\" is not set to \"17\" or does not exist, this is a finding.

    Verify that the \"chrony.conf\" file is configured to an authoritative DoD
time source by running the following command:

    # grep -i server /etc/chrony/chrony.conf
    server tick.usno.navy.mil iburst maxpoll 17
    server tock.usno.navy.mil iburst maxpoll 17
    server ntp2.usno.navy.mil iburst maxpoll 17

    If the parameter \"server\" is not set, is not set to an authoritative DoD
time source, or is commented out, this is a finding.
  "
  desc  'fix', "
    If the system is not networked this requirement is Not Applicable.

    To configure the system clock to compare the system clock at least every 24
hours to the authoritative time source, edit the \"/etc/ntp.conf\" file. Add or
correct the following lines, by replacing \"[source]\" in the following line
with an authoritative DoD time source.

    server [source] iburst maxpoll = 17

    If the \"chrony\" service was running and the value of \"maxpoll\" or
\"server\" was updated then the service must be restarted using the following
command:

    # sudo systemctl restart chrony.service
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag gid: 'V-219331'
  tag rid: 'SV-219331r508662_rule'
  tag stig_id: 'UBTU-18-010501'
  tag fix_id: 'F-21055r305322_fix'
  tag cci: ['SV-109989', 'V-100885', 'CCI-001891']
  tag nist: ['AU-8 (1) (a)']

  is_system_networked = input('is_system_networked')
  
  if is_system_networked

    chrony_conf = '/etc/chrony/chrony.conf'
    chrony_conf_exists = file(chrony_conf).exist?
    
    if chrony_conf_exists
      describe "time sources" do
        server_entries = command('grep "^server" /etc/chrony/chrony.conf').stdout.strip.split("\n").entries

        server_entries.each do |entry|
          describe entry do
            it { should match "^server\s+.*\s+iburst\s+maxpoll\s+=\s+17$" }
          end
        end
      end
    else
      describe chrony_conf + ' exists' do
        subject { chrony_conf_exists }
        it { should be true }
      end
    end
  else
    describe 'System is not networked' do
      skip 'This control is Not Applicable as the system is not networked'
    end
  end
end

