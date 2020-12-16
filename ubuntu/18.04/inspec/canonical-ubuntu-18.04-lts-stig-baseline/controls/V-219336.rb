# encoding: UTF-8

control 'V-219336' do
  title "The Ubuntu operating system must use cryptographic mechanisms to
protect the integrity of audit tools."
  desc  "Protecting the integrity of the tools used for auditing purposes is a
critical step toward ensuring the integrity of audit information. Audit
information includes all information (e.g., audit records, audit settings, and
audit reports) needed to successfully audit information system activity.

    Audit tools include, but are not limited to, vendor-provided and open
source audit tools needed to successfully view and manipulate audit information
system activity and records. Audit tools include custom queries and report
generators.

    It is not uncommon for attackers to replace the audit tools or inject code
into the existing tools with the purpose of providing the capability to hide or
erase system activity from the audit logs.

    To address this risk, audit tools must be cryptographically signed in order
to provide the capability to identify when the audit tools have been modified,
manipulated, or replaced. An example is a checksum hash of the file or files.
  "
  desc  'rationale', ''
  desc  'check', "
    Verify that Advanced Intrusion Detection Environment (AIDE) is properly
configured to use cryptographic mechanisms to protect the integrity of audit
tools.

    Check the selection lines that aide is configured to add/check with the
following command:

    # egrep '(\\/sbin\\/(audit|au))' /etc/aide/aide.conf

    /sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512

    If any of the seven audit tools does not have an appropriate selection
line, this is a finding.
  "
  desc  'fix', "
    Add or update the following selection lines to \"/etc/aide/aide.conf\", in
order to protect the integrity of the audit tools.

    # Audit Tools
    /sbin/auditctl p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/auditd p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/ausearch p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/aureport p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/autrace p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/audispd p+i+n+u+g+s+b+acl+xattrs+sha512
    /sbin/augenrules p+i+n+u+g+s+b+acl+xattrs+sha512
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000278-GPOS-00108'
  tag gid: 'V-219336'
  tag rid: 'SV-219336r508662_rule'
  tag stig_id: 'UBTU-18-010506'
  tag fix_id: 'F-21060r305337_fix'
  tag cci: ['V-100895', 'SV-109999', 'CCI-001496']
  tag nist: ['AU-9 (3)']

  aide_conf = aide_conf input('aide_conf_path')

  aide_conf_exists = aide_conf.exist?

  if aide_conf_exists
    describe aide_conf.where { selection_line == '/sbin/auditctl' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattrs', 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/sbin/auditd' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattrs', 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/sbin/ausearch' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattrs', 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/sbin/aureport' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattrs', 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/sbin/autrace' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattrs', 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/sbin/audispd' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattrs', 'sha512'] }
    end

    describe aide_conf.where { selection_line == '/sbin/augenrules' } do
      its('rules') { should include ['p', 'i', 'n', 'u', 'g', 's', 'b', 'acl', 'xattrs', 'sha512'] }
    end
  else
    describe 'aide.conf file exists' do
      subject { aide_conf_exists }
      it { should be true }
    end
  end
end

