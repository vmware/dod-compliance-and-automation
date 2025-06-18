control 'UBTU-22-252015' do
  title 'Ubuntu 22.04 LTS must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems).

Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in SRG-OS-000355 because a comparison must be done to determine the time difference.'
  desc 'check', %q(Verify Ubuntu 22.04 LTS synchronizes internal system clocks to the authoritative time source when the time difference is greater than one second.

Note: If the system is not networked, this requirement is not applicable.

Check the value of "makestep" by using the following command:

     $ grep -ir makestep /etc/chrony*
     makestep 1 -1

If "makestep" is not set to "1 -1", is commented out, or is missing, this is a finding.

Verify the NTP service is active and the system clock is synchronized with the authoritative time source:

     $ timedatectl | grep -Ei '(synchronized|service)'
     System clock synchronized: yes
     NTP service: active

If the NTP service is not active, this is a finding.

If the system clock is not synchronized, this is a finding.)
  desc 'fix', 'Configure chrony to synchronize the internal system clocks to the authoritative source when the time difference is greater than one second by doing the following:

Edit the "/etc/chrony/chrony.conf" file and add:

     makestep 1 -1

Restart the chrony service:

     $ sudo systemctl restart chrony.service'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 22.04 LTS'
  tag check_id: 'C-64249r1044774_chk'
  tag severity: 'low'
  tag gid: 'V-260520'
  tag rid: 'SV-260520r1044776_rule'
  tag stig_id: 'UBTU-22-252015'
  tag gtitle: 'SRG-OS-000356-GPOS-00144'
  tag fix_id: 'F-64157r1044775_fix'
  tag 'documentable'
  tag cci: ['CCI-004926', 'CCI-002046']
  tag nist: ['SC-45 (1) (b)', 'AU-8 (1) (b)']

  is_system_networked = input('is_system_networked')
  chrony_conf_file_path = input('chrony_conf_file_path')

  if is_system_networked

    describe chrony_conf(chrony_conf_file_path) do
      its('makestep') { should include "1\s-1" }
    end

    describe command('timedatectl status') do
      its('stdout') { should match /System clock synchronized: yes/ }
      its('stdout') { should match /NTP service: active/ }
    end

  else
    impact 0.0
    describe 'This control is Not Applicable as the system is not networked' do
      skip 'This control is Not Applicable as the system is not networked'
    end
  end
end
