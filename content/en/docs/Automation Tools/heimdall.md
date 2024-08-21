---
title: "Heimdall"
weight: 5
description: >
  How to use and install MITRE's Heimdall Server
---

[MITRE's Heimdall Server](https://github.com/mitre/heimdall2) allows you to visualize, store, and compare scan results from various security tools.

## Prerequisites

* Infrastructure to deploy Heimdall Server on.

## Installation

Heimdall is most easily deployed via Docker or Kubernetes. 

Demo instances are available at [Heimdall Lite](https://heimdall-lite.mitre.org/) or [Heimdall](https://heimdall-demo.mitre.org/). 

*Note: The demo environments are for demonstration use only, please do not provide any personal identifying information or load real mission data into this system, even if the data is from non-production environments.*

For a full list of installation options, see [Installation](https://github.com/mitre/heimdall2#getting-started--installation).

## Usage
All of the documentation below will be in the context of working with InSpec results. Using results from other tools may vary.  

### Viewing Results

After login in you can simply drag your files over to the window to load or click "Choose files to upload" and browse to your result file.  
![Heimdall Load File]({{< baseurl >}}images/heimdall_load_file.png)

After loading a result you are shown a visualization of that result where you can view the compliance status and filter the results based on any available criteria, for example, only showing controls that failed.  
![Heimdall Results View]({{< baseurl >}}images/heimdall_view_result.png)

Further down the page you can drill down into the specifics of each control and the test results.  
![Heimdall Test Results View]({{< baseurl >}}images/heimdall_view_result2.png)

### Exporting Results
Results can also be exported to various other formats as shown in the screenshot below.  
![Heimdall Export]({{< baseurl >}}images/heimdall_export_options.png)

### Comparing Results
If you have more than one scan you would like to compare from like scan results you can load them both and enable the comparison view using the button show below.  
![Heimdall Compare Button]({{< baseurl >}}images/heimdall_comparison_button.png)

After the comparison view is enabled you are presented with visualization of the differences between the two results and which controls changed status.  
![Heimdall Compare View]({{< baseurl >}}images/heimdall_comparison_view.png)

## References
For the more information, see the [Heimdall Github Page](https://github.com/mitre/heimdall2).