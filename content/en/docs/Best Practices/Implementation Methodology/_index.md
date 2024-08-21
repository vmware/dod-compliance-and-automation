---
title: "Implementation Methodology"
linkTitle: "Implementation Methodology"
weight: 3
description: >
  VMware STIG Implementation Methodology
---

The last thing any system administrator wants to do is break the systems they are responsible for by hardening them. Implementing STIG controls in a methodical and consistent manner will reduce the risk of operational impacts to an organizations environment.  

## Workflow
The workflow below can be applied to any product whether it is delivered as an applicance or not. If a product is not an appliance you can skip that part of the workflow.  
![STIG Workflow]({{< baseurl >}}images/bp_workflow.png)

## Tips
-	Whenever possible, it is highly recommended to test any hardening guidance in a test environment first. This will help you get familiar with the procedures and tools involved in the process.
- Make sure you have a backout plan! Snapshots, backups, copies of files before modification are all good ideas.
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

## vSphere Example
If we apply this workflow to vSphere 7 or 8 it would look like this at a high level.  

1. Apply Product STIGs with functional testing in between each STIG
    - ESXi
    - vCenter
    - Virtual Machines
2. Apply vCenter Appliance STIGs with functional testing in between each STIG
    - EAM
    - Lookupsvc
    - Perfcharts
    - Photon
    - PostgreSQL
    - Rhttpproxy/Envoy
    - STS
    - UI
    - VAMI

It is important to focus on one STIG at a time so that any issues identified during functional testing can be quickly narrowed down.  

### Incremental Implementations
It is also a valid strategy, especially in larger environments with multiple vCenters and clusters, to incrementally implement STIGs to one site, vCenter, or vSphere cluster at a time to identify any issues without impacting the entire environment.  

When pursuing this approach here are some items to consider:  
- Do not mix hardened with non-hardened ESXi hosts in the same cluster.
- If multiple vCenter servers exist consider how they are linked to each other or share an SSO domain.