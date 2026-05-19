control 'UBTU-24-600160' do
  title 'Ubuntu 24.04 LTS must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations must consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).

'
  desc 'check', 'Note: If the system is not networked, this requirement is not applicable.

Verify Ubuntu 24.04 LTS is configured to compare the system clock at least every 24 hours to an authoritative time source with the following command:

$ sudo grep -ir maxpoll /etc/chrony*
server [source] iburst maxpoll 16

If the parameter "server" is not set, is not set to an authoritative DOD time source, or is commented out, this is a finding.

If the "maxpoll" option is set to a number greater than 16, the line is commented out, or is missing, this is a finding.'
  desc 'fix', 'To configure the system clock to compare to the authoritative time source at least every 24 hours, edit the "/etc/chrony/chrony.conf" file. Add or correct the following lines, by replacing "[source]" in the following line with an authoritative time source:

server [source] iburst maxpoll 16

If the "chrony" service was running and the value of "maxpoll" or "server" was updated, the service must be restarted using the following command:

$ sudo systemctl restart chrony.service'
  impact 0.3
  tag check_id: 'C-74784r1066740_chk'
  tag severity: 'low'
  tag gid: 'V-270751'
  tag rid: 'SV-270751r1066742_rule'
  tag stig_id: 'UBTU-24-600160'
  tag gtitle: 'SRG-OS-000785-GPOS-00250'
  tag fix_id: 'F-74685r1066741_fix'
  tag satisfies: ['SRG-OS-000785-GPOS-00250', 'SRG-OS-000355-GPOS-00143']
  tag 'documentable'
  tag cci: ['CCI-004922', 'CCI-004923']
  tag nist: ['SC-45', 'SC-45 (1) (a)']

  is_system_networked = input('is_system_networked')
  chrony_conf_file_path = input('chrony_conf_file_path')

  if is_system_networked

    chrony_conf_exists = file(chrony_conf_file_path).exist?

    if chrony_conf_exists
      describe 'time sources' do
        server_entries = file(chrony_conf_file_path).content.lines.select do |line|
          line =~ /^\s*server\s+/ && !line.strip.start_with?('#')
        end

        describe 'Chrony server configuration' do
          it 'should have at least one active server entry' do
            expect(server_entries).not_to be_empty
          end
        end

        server_entries.each do |entry|
          describe entry do
            it { should match(/^server\s+\S+.*\bmaxpoll\s+16\b/) }
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
