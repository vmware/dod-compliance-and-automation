control 'PHTN-30-000040' do
  title 'The Photon operating system "/var/log" directory must be owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state and can provide sensitive information to an unprivileged attacker."
  desc 'check', 'At the command line, run the following command:

# stat -c "%n is owned by %U and group owned by %G" /var/log

If the "/var/log directory" is not owned by root, this is a finding.'
  desc 'fix', 'At the command line, run the following command:

# chown root:root /var/log'
  impact 0.5
  tag check_id: 'C-60190r887217_chk'
  tag severity: 'medium'
  tag gid: 'V-256515'
  tag rid: 'SV-256515r887219_rule'
  tag stig_id: 'PHTN-30-000040'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-60133r887218_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

  describe directory('/var/log') do
    its('owner') { should cmp 'root' }
  end
end
