# -*- encoding : utf-8 -*-
control "VCSA-70-000290" do
  title "The vCenter Server must limit membership to the SystemConfiguration.BashShellAdministrators SSO group."
  desc  "
    vCenter SSO integrates with PAM in the underlying Photon operating system so that members of the SystemConfiguration.BashShellAdministrators SSO group can log on to the operating system without needing a separate account. The caveat to this is that even though unique SSO users log on, they are transparently using a group account named \"sso-user\" as far as Photon auditing is concerned. While the audit trail can still be traced back to the individual SSO user, it is a more involved process.
    
    In order to force accountability and non-repudiation, the SSO group SystemConfiguration.BashShellAdministrators must be severly restricted. 
  "
  desc  "rationale", ""
  desc  "check", "
    From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Groups.
    
    Click the next page arrow until you see the \"SystemConfiguration.BashShellAdministrators\" group.
    
    Click \"SystemConfiguration.BashShellAdministrators\".
    
    Review the members of the group and ensure that only authorized accounts are present.
    
    Note: These accounts act as root on the Photon operating system and have the ability to severely damage vCenter, inadvertently or otherwise.
    
    If there are any accounts present as members of SystemConfiguration.BashShellAdministrators that are not authorized, this is a finding.
  "
  desc  "fix", "
    From the vSphere Client, go to Administration >> Single Sign On >> Users and Groups >> Groups.
    
    Click the next page arrow until you see the \"SystemConfiguration.BashShellAdministrators\" group.
    
    Click \"SystemConfiguration.BashShellAdministrators\".
    
    Click the three vertical dots next to the name of each unauthorized account.
    
    Select \"Remove Member\".
  "
  impact 0.5
  tag severity: "medium"
  tag gtitle: "SRG-APP-000516"
  tag gid: nil
  tag rid: nil
  tag stig_id: "VCSA-70-000290"
  tag cci: ["CCI-000366"]
  tag nist: ["CM-6 b"]

  describe "This check is a manual or policy based check" do
    skip "This must be reviewed manually"
  end
end