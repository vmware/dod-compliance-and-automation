control "ESXI-67-000071" do
  title "The SA must verify the integrity of the installation media before
installing ESXi."
  desc  "Always check the SHA1 or MD5 hash after downloading an ISO, offline
bundle, or patch to ensure integrity and authenticity of the downloaded files."
  impact 1.0
  tag severity: "CAT I"
  tag gtitle: "SRG-OS-000480-VMM-002000"
  tag rid: "ESXI-67-000071"
  tag stig_id: "ESXI-67-000071"
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  desc 'check', "The downloaded ISO, offline bundle, or patch hash must be
verified against the vendor's checksum to ensure the integrity and authenticity
of the files.

See some typical command line example(s) for both the md5 and sha1 hash
check(s) directly below.

# md5sum <filename>.iso
# sha1sum <filename>.iso

If any of the system's downloaded ISO, offline bundle, or system patch hashes
cannot be verified against the vendor's checksum, this is a finding."
  desc 'fix', "If the hash returned from the md5sum or sha1sum commands do not
match the vendor's hash, the downloaded software must be discarded.

If the physical media is obtained from VMware and the security seal is broken,
the software must be returned to VMware for replacement."

  describe "" do
    skip 'Manual verification is required for this control'
  end

end

