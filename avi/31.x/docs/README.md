# VMware Avi Load Balancer STIG Documentation

## Overview
An XCCDF formatted XML is provided for the Avi Load Balancer STIG Readiness Guide content for use to view in [STIG Viewer](https://public.cyber.mil/stigs/stig-viewing-tools/).  

This can be consumed from the zip file included in this directory.

## XCCDF zip bundle

The **`U_VMware_NSX_Advanced_Load_Balancer_STIG_Readiness_Guide_v1r1.zip`** file here is the same **STIG Readiness Guide** archive that shipped with the prior NSX Advanced Load Balancer naming; it is **not generated from this repository**.

To supply a **31.x–specific** (or Avi–branded) bundle when it exists:

1. Obtain the official release from **DoD Cyber Exchange** ([public.cyber.mil](https://public.cyber.mil/stigs/)) and/or your **VMware by Broadcom** STIG/readiness distribution channel, when a guide that matches Avi Load Balancer 31.x is published.
2. Replace the zip in this folder and update this README (and `saf-manifest.json` if applicable) with the **new filename** and version/date metadata.

Until an updated archive is published, keep this zip as a **reference** for STIG Viewer import; control text in the InSpec profile under `../inspec/` is what this repo maintains for **31.x** automation.

## Known Issues
Any known issues will be documented in the known-issues.md document located here.  
