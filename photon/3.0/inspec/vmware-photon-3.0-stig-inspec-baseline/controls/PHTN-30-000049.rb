control 'PHTN-30-000049' do
  title 'The Photon operating system must limit privileges to change software resident within software libraries.'
  desc  'On the Photon operating system, system-wide shared library files, which are linked to executables during process load time or run time, are stored in /usr/lib by default. All files on those paths must be owned by root in order to help prevent tampering and unintended behavior.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, execute the following command:

    # find /usr/lib/ -type f \"(\" ! -user root -o ! -group root -o -perm /022 \")\" -printf '%p, %u:%g:%m\
    '

    If there is any output, this is a finding.
  "
  desc 'fix', "
    At the command line, execute the following command for each file returned for user and group ownership:

    # chown root:root <file>

    At the command line, execute the following command for each file returned for file permissions:

    # chmod 755 <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'PHTN-30-000049'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  describe command("find /usr/lib/ -type f \"(\" ! -user root -o ! -group root -o -perm /022 \")\" -printf '%p, %u:%g:%m\\n'") do
    its('stdout') { should cmp '' }
  end
end
