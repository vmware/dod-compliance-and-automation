control 'PHTN-40-000161' do
  title 'The Photon operating system must remove all software components after updated versions have been installed.'
  desc  'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by adversaries. Some information technology products may remove older versions of software automatically from the information system.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command:

    # grep -i \"^clean_requirements_on_remove\" /etc/tdnf/tdnf.conf

    Expected result:

    clean_requirements_on_remove=true

    If the output does not match the expected result, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/tdnf/tdnf.conf

    Add or update the following line:

    clean_requirements_on_remove=true
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag gid: 'V-PHTN-40-000161'
  tag rid: 'SV-PHTN-40-000161'
  tag stig_id: 'PHTN-40-000161'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']

  describe command('grep -i "^clean_requirements_on_remove" /etc/tdnf/tdnf.conf') do
    its('stdout.strip') { should cmp 'clean_requirements_on_remove=true' }
  end
end
