control 'PHTN-50-000085' do
  title 'The Photon operating system must limit privileges to change software resident within software libraries.'
  desc  "
     If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

    This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify software library permissions are not writable by others:

    # find /usr/lib/ -type f -perm -o+w -printf '%p, %u:%g:%m\
    '

    If there is any output, this is a finding.
  "
  desc 'fix', "
    At the command line, run the following for each file returned:

    # chmod o-w <file>
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-PHTN-50-000085'
  tag rid: 'SV-PHTN-50-000085'
  tag stig_id: 'PHTN-50-000085'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  badfiles = command('find /usr/lib/ -type f -perm -o+w').stdout
  badfilesstderr = command('find /usr/lib/ -type f -perm -o+w').stderr

  if !badfiles.empty?
    badfiles.split.each do |badfile|
      describe file(badfile) do
        it { should_not be_writable.by('others') }
      end
    end
  else
    describe 'Files found with world writable permissions under /usr/lib' do
      subject { badfiles }
      it { should be_empty }
    end
    describe 'Find command should not have errors' do
      subject { badfilesstderr }
      it { should cmp '' }
    end
  end
end
