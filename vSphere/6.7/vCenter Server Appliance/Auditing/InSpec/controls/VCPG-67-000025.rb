control "VCPG-67-000025" do
  title "The vPostgres database security updates and patches must be installed
in a timely manner in accordance with site policy."
  desc  "Security flaws with software applications, including database
management systems, are discovered daily. Vendors are constantly updating and
patching their products to address newly discovered security vulnerabilities.
Organizations (including any contractor to the organization) are required to
promptly install security-relevant software updates (e.g., patches, service
packs, and hot fixes). Flaws discovered during security assessments, continuous
monitoring, incident response activities, or information system error handling
must also be addressed expeditiously.

    Organization-defined time periods for updating security-relevant software
may vary based on a variety of factors including, for example, the security
category of the information system or the criticality of the update (i.e.,
severity of the vulnerability related to the discovered flaw).

    This requirement will apply to software patch management solutions that are
used to install patches across the enclave and also to applications themselves
that are not part of that patch management solution. For example, many browsers
today provide the capability to install their own patch software. Patch
criticality, as well as system criticality, will vary. Therefore, the tactical
situations regarding the patch management process will also vary. This means
that the time period utilized must be a configurable parameter. Time frames for
application of security-relevant software updates may be dependent upon the
Information Assurance Vulnerability Management (IAVM) process.

    The application will be configured to check for and install
security-relevant software updates within an identified time period from the
availability of the update. The specific time period will be defined by an
authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).
  "
  tag component: "postgres"
  tag severity: nil
  tag gtitle: "SRG-APP-000456-DB-000390"
  tag gid: nil
  tag rid: "VCPG-67-000025"
  tag stig_id: "VCPG-67-000025"
  tag fix_id: nil
  tag cci: "CCI-002605"
  tag nist: ["SI-2 c", "Rev_4"]
  tag false_negatives: nil
  tag false_positives: nil
  tag documentable: nil
  tag mitigations: nil
  tag severity_override_guidance: nil
  tag potential_impacts: nil
  tag third_party_tools: nil
  tag mitigation_controls: nil
  tag responsibility: nil
  tag ia_controls: "SI-2 c"
  tag check: "Obtain supporting documentation from the ISSO.

Review the policies and procedures used to ensure that all security-related
upgrades are being installed within the configured time period directed by an
authoritative source.

If all security-related upgrades are not being installed within the configured
time period directed by an authoritative source, this is a finding."
  tag fix: "Ensure that patches and updates from an authoritative source are
applied at least within 24 hours after they have been received."
end

