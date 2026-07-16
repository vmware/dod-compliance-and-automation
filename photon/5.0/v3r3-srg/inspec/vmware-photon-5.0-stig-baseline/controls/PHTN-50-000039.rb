control 'PHTN-50-000039' do
  title 'The operating system must store only encrypted representations of passwords.'
  desc  'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.'
  desc  'rationale', ''
  desc  'check', "
    At the command line, run the following command to verify passwords are stored with only encrypted representations:

    # grep ^ENCRYPT_METHOD /etc/login.defs

    Example result:

    ENCRYPT_METHOD SHA512

    If the \"ENCRYPT_METHOD\" option is not set to \"SHA512\", is missing or commented out, this is a finding.
  "
  desc 'fix', "
    Navigate to and open:

    /etc/login.defs

    Add or update the following line:

    ENCRYPT_METHOD SHA512
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag gid: 'V-PHTN-50-000039'
  tag rid: 'SV-PHTN-50-000039'
  tag stig_id: 'PHTN-50-000039'
  tag cci: ['CCI-004062']
  tag nist: ['IA-5 (1) (d)']

  describe login_defs do
    its('ENCRYPT_METHOD') { should cmp 'SHA512' }
  end
end
