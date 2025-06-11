---
title: "Implementation Methodology"
linkTitle: "Implementation Methodology"
weight: 3
description: >
  VMware STIG Implementation Methodology
---
## Overview
The last thing any system administrator wants to do is break the systems they are responsible for by hardening them. Implementing STIG controls in a methodical and consistent manner will reduce the risk of operational impacts to an organization's environment.  

Before beginning any assessment or remediation activities it is recommended to familiarize yourself with the guidance and rules provided so that informed decisions can be made and potential issues avoided. There are many methodologies to audit and remediate STIG rules and in this section we will offer a recommended workflow to follow in your environment. As always please take the necessary steps to backup configurations and protect your critical data before performing any changes to your environment. Each environment will also differ in how it is operated and rules that may hinder the operation should be carefully evaluated for needed design changes, risk mitigations, or alternative implementations.  

### Automation
In addition to the guidance provided, Broadcom also develops and provides automation to audit and remediate rules where possible. It is highly recommended to take advantage of this automation for the best experience.
For more information on the available automation, please visit our [DOD Compliance and Automation Github](https://github.com/vmware/dod-compliance-and-automation/) page or reach out to your account team for more details on our compliance offerings.  

### Compliant by Design
A given rule will either be in a compliant state by default or in need of remediation to bring it into a compliant state.  Many of the rules included in this guidance are in a compliant state by default but still must be continuously assessed to ensure they remain in a desirable state.  The remaining rules needing remediation often require post deployment configuration but regardless of the reason our goal is a compliant by design state with minimal post deployment configuration.  

## Workflow
The workflow presented is an example methodology for STIG assessment and remediation that is intended to provide a repeatable process that generates needed artifacts while also reducing the risk of impacting the operation of the target environment.

![STIG Workflow]({{< baseurl >}}images/bp_workflow.png)

{{% alert title="Tips" color="dark" %}}
-	Whenever possible, it is highly recommended to evaluate any hardening guidance in a test environment first. This will help you get familiar with the procedures and tools involved in the process.
- Make sure you have a back out plan! Snapshots, backups, and making copies of files before modification are all good ideas.
-	Perform service restarts and/or appliance restarts after each appliance component is remediated. Many problems will not manifest until this is done.
-	If you are not 100% sure what a control is asking you to do, ask a co-worker to review it or reach out for clarification as detailed in the support section.
- If the results from checking a control don't make sense, ask a co-worker to review it or reach out for clarification as detailed in the support section.
-	Get familiar with the available automation tools and how they work before going all in on the automation content that is available.
-	Run any existing daily health checks or common tasks in your environment to confirm functionality along the way.
- Check for updated guidance before starting.
- Always match the product version the guidance is intended for with the product version in use.
- Read finding statements carefully. Some controls may not be applicable in your scenario.
- Consider how your environment is operated for impacts. If some of your tools or integrations utilize SSH to function then disabling SSH will impact daily operations and alternatives should be explored or risk accepted to waive a control by the appropriate authority.
- Document changes so you and your co-workers can remember what changes were made.
{{% /alert %}}

### Incremental Implementations
It is also a valid strategy, especially in larger environments with multiple vCenters and clusters, to incrementally implement STIGs to one site, vCenter, or vSphere cluster at a time to figure out any issues without impacting the entire environment.  

When pursuing this approach here are some items to consider:  
- Do not mix hardened with non-hardened ESXi hosts in the same cluster.
- If multiple vCenter servers exist consider how they are linked to each other or share an SSO domain.