# encoding: UTF-8

control 'PHTN-30-000051' do
  title 'The Photon operating system package files must not be modified.'
  desc  'rationale', ''
  desc  'check', "
    Use the verification capability of rpm to check the MD5 hashes of the audit
files on disk versus the expected ones from the installation package. At the
command line, execute the following command:

    # rpm -V audit | grep \"^..5\" | grep -v \"^...........c\"

    If there is output, this is a finding.
  "
  desc  'fix', "If the audit system binaries have been altered the system must
be taken offline and your ISSM must be notified immediately. Reinstalling the
audit tools is not supported. The appliance should be restored from a backup, a
snapshot or redeployed once the root cause is remediated."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag stig_id: 'PHTN-30-000051'
  tag cci: 'CCI-001496'
  tag nist: ['AU-9 (3)']

  describe command('rpm -V audit | grep "^..5" | grep -v "^...........c"') do
      its ('stdout') { should eq '' }
  end

end

