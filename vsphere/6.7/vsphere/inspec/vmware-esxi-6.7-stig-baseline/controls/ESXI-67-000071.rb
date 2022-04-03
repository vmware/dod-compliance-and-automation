control 'ESXI-67-000071' do
  title "The SA must verify the integrity of the installation media before
installing ESXi."
  desc  "Always check the SHA1 or MD5 hash after downloading an ISO, offline
bundle, or patch to ensure integrity and authenticity of the downloaded files."
  desc  'rationale', ''
  desc  'check', "
    The downloaded ISO, offline bundle, or patch hash must be verified against
the vendor's checksum to ensure the integrity and authenticity of the files.

    See some typical command line example(s) for both the md5 and sha1 hash
check(s) below:

    # md5sum <filename>.iso
    # sha1sum <filename>.iso

    If any of the system's downloaded ISO, offline bundle, or system patch
hashes cannot be verified against the vendor's checksum, this is a finding.
  "
  desc 'fix', "
    If the hash returned from the \"md5sum\" or \"sha1sum\" commands do not
match the vendor's hash, the downloaded software must be discarded.

    If the physical media is obtained from VMware and the security seal is
broken, the software must be returned to VMware for replacement.
  "
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag gid: 'V-239324'
  tag rid: 'SV-239324r674901_rule'
  tag stig_id: 'ESXI-67-000071'
  tag fix_id: 'F-42516r674900_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']

  describe 'This check is a manual or policy based check' do
    skip 'This must be reviewed manually'
  end
end
