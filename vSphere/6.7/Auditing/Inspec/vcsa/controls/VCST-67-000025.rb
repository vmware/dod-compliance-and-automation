control "VCST-67-000025" do
  title "The Security Token Service must not enable support for TRACE requests."
  desc  "\"Trace\" is a technique for a user to request internal information
about Tomcat. This is useful during product development, but should not be
enabled in production.  Allowing a attacker to conduct a Trace operation
against the Security Token Service will expose information that would be useful
to perform a more targeted attack. The Security Token Service provides the
allowTrace parameter as means to disable responding to Trace requests."
  impact 0.5
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000266-WSR-000160"
  tag gid: nil
  tag rid: "VCST-67-000025"
  tag stig_id: "VCST-67-000025"
  tag fix_id: nil
  tag cci: "CCI-001312"
  tag nist: ["SI-11 a", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "SI-11 a"
  tag check: "At the command prompt, execute the following command:

# grep allowTrace /usr/lib/vmware-sso/vmware-sts/conf/server.xml

If allowTrace is set to \"true\", this is a finding. If no line is returned
this is NOT a finding."
  tag fix: "Navigate to and open /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Navigate to and locate 'allowTrace=\"true\"'

Remove the 'allowTrace=\"true\"' setting."

  describe.one do
    describe xml('/usr/lib/vmware-sso/vmware-sts/conf/server.xml') do
      its(['Server/Service/Connector/attribute::allowTrace']) { should eq [] }
    end

    describe xml('/usr/lib/vmware-sso/vmware-sts/conf/server.xml') do
      its(['Server/Service/Connector/attribute::allowTrace']) { should cmp "false" }
    end
  end

end