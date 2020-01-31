control "VCUI-67-000006" do
  title "vSphere UI must generate log records for system startup and shutdown."
  desc  "Logging must be started as soon as possible when a service starts and
when a service is stopped. Many forms of suspicious actions can be detected by
analyzing logs for unexpected service starts and stops. Also, by starting to
log immediately after a service starts, it becomes more difficult for suspicous
activity to go un-logged.

    On the VCSA, the vmware-vmon service starts up the JVMs for various vCenter
processes, including vSphere UI, and the individual json config files control
the early jvm logging. Ensuring these json files are configured correctly
enables early java stdout and stderr logging.
  "
  impact CAT II
  tag severity: "CAT II"
  tag gtitle: "SRG-APP-000266-WSR-000160"
  tag gid: nil
  tag rid: "VCUI-67-000006"
  tag stig_id: "VCUI-67-000006"
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

# grep StreamRedirectFile /etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json

Expected result:

\"StreamRedirectFile\":
\"%VMWARE_LOG_DIR%/vmware/vsphere-ui/logs/vsphere-ui-runtime.log\",

If there is no log file specified for the StreamRedirectFile setting, this is a
finding."
  tag fix: "Navigate to and open
/etc/vmware/vmware-vmon/svcCfgfiles/vsphere-ui.json . Below the last line of
the 'PreStartCommandArg' block add or re-configure the following line:

\"StreamRedirectFile\":
\"%VMWARE_LOG_DIR%/vmware/vsphere-ui/logs/vsphere-ui-runtime.log\",

Restart the appliance for changes to take effect."
end

