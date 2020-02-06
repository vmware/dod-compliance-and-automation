control "VCPF-67-000011" do
  title "Performance Charts must have Multipurpose Internet Mail Extensions
(MIME) that invoke OS shell programs disabled."
  desc  "MIME mappings tell the Performance Charts what type of program various
file types and extensions are and what external utilities or programs are
needed to execute the file type. By ensuring that various shell script
MIME types are not included in web.xml, the server is protected against
malicious users tricking the server into executing shell command files."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000141-WSR-000081"
  tag gid: nil
  tag rid: "VCPF-67-000011"
  tag stig_id: "VCPF-67-000011"
  tag fix_id: nil
  tag cci: nil
  tag nist: nil
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: nil
  tag check: "At the command prompt, execute the following command:

# grep -En '(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)'
/usr/lib/vmware-perfcharts/tc-instance/conf/web.xml

If the command produces any output, this is a finding."
  tag fix: "Open /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml in a text
editor. Remove any and all of the following nodes lines.

<mime-type>application/x-csh</mime-type>
<mime-type>application/x-shar</mime-type>
<mime-type>application/x-sh</mime-type>
<mime-type>application/x-ksh</mime-type>"

  describe command('grep -En \'(x-csh<)|(x-sh<)|(x-shar<)|(x-ksh<)\' /usr/lib/vmware-perfcharts/tc-instance/conf/web.xml') do
    its ('stdout.strip') { should eq '' }
  end

end