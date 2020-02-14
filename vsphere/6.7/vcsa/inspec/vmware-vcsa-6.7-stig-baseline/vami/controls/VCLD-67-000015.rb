control "VCLD-67-000015" do
  title "VAMI server files must be verified for their integrity (e.g.,
checksums and hashes) before becoming part of the production web server."
  desc  "Being able to verify that a patch, upgrade, certificate, etc., being
added to the web server is unchanged from the producer of the file is essential
for file validation and non-repudiation of the information.

    VMware delivers product updates and patches regularly.  It is crucial that
system administrators coordinate installation of product updates with the site
ISSO to ensure that only valid files are uploaded onto the system."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000131-WSR-000051"
  tag gid: nil
  tag rid: "VCLD-67-000015"
  tag stig_id: "VCLD-67-000015"
  tag cci: "CCI-001749"
  tag nist: ["CM-5 (3)", "Rev_4"]
  desc 'check', "At the command prompt, execute the following command:

rpm -qa|grep lighttpd|xargs rpm -V

If the command returns output for any file other than
/opt/vmware/etc/lighttpd/lighttpd.conf , this is a finding."
  desc 'fix', "If the VAMI binaries have been modified from the default state when
deployed as part of the VCSA then the system must be wiped and redeployed or
restored from backup. VMware does not recommend or support recovering from such
a state by reinstalling RPMs or similar efforts."

  describe command('rpm -qa|grep lighttpd|xargs rpm -V') do
    its ('stdout.strip') { should match "S.5....T.  c /opt/vmware/etc/lighttpd/lighttpd.conf"}
  end

end

