control "PHTN-10-000079" do
  title "The Photon operating system must ensure that root $PATH entries are
appropriate."
  desc  "The $PATH variable contains semi-colon delimited set of directories
that allows root to not specify the full path for a limited set of binaries.
Having unexpected directories in $PATH can lead to root running a binary other
than the one intended."
  tag severity: nil
  tag gtitle: "SRG-OS-000480-GPOS-00227"
  tag gid: nil
  tag rid: "PHTN-10-000079"
  tag stig_id: "PHTN-10-000079"
  tag fix_id: nil
  tag cci: "CCI-000366"
  tag nist: ["CM-6 b", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "CM-6 b"
  tag check: "At the command line, execute the following command:

# echo $PATH

Expected result:

/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/java/jre-vmware/bin:/opt/vmware/bin

If the output does not match the expected result, this is a finding."
  tag fix: "At the command line, execute the following command:

# export
PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/java/jre-vmware/bin:/opt/vmware/bin"

  describe command('echo $PATH') do
      its ('stdout.strip') { should cmp '/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/usr/java/jre-vmware/bin:/opt/vmware/bin' }
  end

end

