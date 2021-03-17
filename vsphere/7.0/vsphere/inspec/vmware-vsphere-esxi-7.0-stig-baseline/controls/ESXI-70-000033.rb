# encoding: UTF-8

control 'ESXI-70-000033' do
  title "The password hashes stored on the ESXi host must have been generated
using a FIPS 140-2 approved cryptographic hashing algorithm."
  desc  "Systems must employ cryptographic hashes for passwords using the SHA-2
family of algorithms or FIPS 140-2 approved successors. The use of unapproved
algorithms may result in weak password hashes more vulnerable to compromise."
  desc  'rationale', ''
  desc  'check', "
    From an ESXi shell, run the following command(s):

    # grep -i \"^password\" /etc/pam.d/passwd | grep sufficient

    If sha512 is not listed, this is a finding.
  "
  desc  'fix', "
    From an ESXi shell, add or correct the following line in
/etc/pam.d/passwd:

    password sufficient /lib/security/$ISA/pam_unix.so use_authtok nullok
shadow sha512 remember=5
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000033'
  tag fix_id: nil
  tag cci: 'CCI-000366'
  tag nist: ['CM-6 b']

  describe "This check is a manual or policy based check" do
    skip "This must be reviewed manually"
  end

end

