control 'PHTN-30-000066' do
  title 'The Photon operating system must remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc 'check', 'At the command line, run the following command:

# grep -i "^clean_requirements_on_remove" /etc/tdnf/tdnf.conf

Expected result:

clean_requirements_on_remove=true

If the output does not match the expected result, this is a finding.'
  desc 'fix', 'Navigate to and open:

/etc/tdnf/tdnf.conf

Remove any existing "clean_requirements_on_remove" line and ensure the following line is present:

clean_requirements_on_remove=true'
  impact 0.5
  tag check_id: 'C-60211r887280_chk'
  tag severity: 'medium'
  tag gid: 'V-256536'
  tag rid: 'SV-256536r887282_rule'
  tag stig_id: 'PHTN-30-000066'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag fix_id: 'F-60154r887281_fix'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']

  describe command('grep -i "^clean_requirements_on_remove" /etc/tdnf/tdnf.conf') do
    its('stdout.strip') { should cmp 'clean_requirements_on_remove=true' }
  end
end
