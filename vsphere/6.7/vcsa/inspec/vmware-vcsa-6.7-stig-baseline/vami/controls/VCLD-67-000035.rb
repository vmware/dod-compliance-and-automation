control "VCLD-67-000035" do
  title "VAMI must have all security-relevant software updates installed within
the configured time period directed by an authoritative source."
  desc  "Security flaws with software applications are discovered daily.
Vendors are constantly updating and patching their products to address newly
discovered security vulnerabilities. Organizations (including any contractor to
the organization) are required to promptly install security-relevant software
updates (e.g., patches, service packs, and hot fixes). Flaws discovered during
security assessments, continuous monitoring, incident response activities, or
information system error handling must also be addressed expeditiously.

    The web server will be configured to check for and install
security-relevant software updates from an authoritative source within an
identified time period from the availability of the update. By default, this
time period will be every 24 hours.

    VMware delivers product updates and patches regularly.  It is crucial that
system administrators coordinate installation of product updates with the site
ISSO to ensure that updated and patched files are uploaded onto the system as
soon as prescribed."
  tag component: "vami"
  tag severity: nil
  tag gtitle: "SRG-APP-000456-WSR-000187"
  tag gid: nil
  tag rid: "VCLD-67-000035"
  tag stig_id: "VCLD-67-000035"
  tag cci: "CCI-002605"
  tag nist: ["SI-2 c", "Rev_4"]
  desc 'check', "VAMI is updated along with the VCSA as a whole. The SA must keep
the VCSA up to date on security patches and apply them according to ISSO
requirements."
  desc 'fix', "VAMI is updated along with the VCSA as a whole. The SA must keep
the VCSA up to date on security patches and apply them according to ISSO
requirements."


end

