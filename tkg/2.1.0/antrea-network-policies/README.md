# Antrea Cluster Network Policies for CISA/NSA
The CISA/NSA Kubenretes Hardening guide recommends the use of network policies. This repository contains the default policies needed to comply with NSA/CISA. It utilizes ClusterNetworkPolicies and Network Policies Provided by Antrea in lieu of the Kubernets Network Policies. This was done because the ClusterNetworkPolicy can be applied across the entire cluster as compared to just at the namespace level. Antrea's network policies follow a tiered approach as outlined [here](https://antrea.io/docs/v1.7.1/docs/antrea-network-policy/#tier).In short numerous default tiers are provided emergency, securityOps, Network Ops, Platform, Application, and Baseline. All of the tiers outside of the baseline are applied before the K8s Network Policies and the baseline is applied after it. Custom Tiers can be created using the Tier CRD with different priority levels to go in between any of the other tiers. Within each tier every policy has a priority level the lowest number priority will be analyzed first. The first match to a policy will be used when deciding how to handle the traffic so if the traffic is dropped by a kubernetes network policy or an earlier tier it does not matter if it is allowed in a later tier or within the kubernets network policies. Finally each policy can have numerous rules associated with it and order matters here as well.

# Network Policies Checklist CISA/NSA
The checklist in the Hardening guide is below:
* Use CNI plugin that supports NetworkPolicy API 
* Create policies that select Pods using podSelector and/or the namespaceSelector 
* Use a default policy to deny all ingress and egress traffic. Ensures unselected Pods are isolated to all namespaces except kube-system
* Use LimitRange and ResourceQuota policies to limit resources on a namespace or Pod level 

The first 3 of these are covered by the policies in this repository. The 4th one is unrelated to network policies directly but will be covered in another repo.

TKG uses Antrea which is a CNI plugin that supports the NetworkPolicyAPI. The ClusterNetworkPolicies provided by Antrea as well as the Kubernetes Network Policies both have support for podSelector and namespaceSelector and are utilized in the policies provided in this repo. The default deny policy in this repository selects all namespaces and denies traffic both in and out of the pod to anywhere.


# TKGm 1.6.1 and below
## Files with dynamic IPs

| File Name | IP |
| ---------- | ---- |
|[Pinniped LoadBalancer](tkg/pinniped/pinniped.yaml)|Pinniped Load Balancer IP|
|[Pinniped OIDC Provider](tkg/pinniped/pinniped.yaml)|Pinniped OIDC FQDN|
|[Cert Manager to Contour](tkg/cert-manager/ingress-certs/cert-manager-egress-public-ip.yaml)| Contour load balancer ips|
|[Antrea GW Webhooks - Management Cluster](tkg/management/antrea-gw.yaml)|Control Plane's Antrea GW|
|[Antrea GW Webhooks Cert-Manager/Metrics-Server](tkg/antrea-gw.yaml)|Control Plane's Antrea GW|
|[Gatekeeper System](tkg/gatekeeper/allow-to-nodes.yaml)|Node Subnet|
|[Envoy](tkg/contour/envoy.yaml)|All Nodes Antrea GW|
|[Falcosidekick](tkg/falco/falco-ouputs.yaml)| Update ES rule with your logging sytem IP|
|[Falcosidekick](tkg/falco/antrea-gw.yaml)| Update will all nodes antrea GWs|
|[Kube System Hardening](tkg/kube-system.yaml)|Worker Node Subnet|
|[Core DNS](tkg/core-dns.yaml)|IP of nameserver and Antrea GW for all nodes|

# TKGm 2.1.0 and above
TKGm 2.1.0 added in node selectors which makes the manual updating of antrea gw and node ips in network policies obsolete. These are now handled without manual user entry as such the list of dynamic IPs that need updating has been reduced drastically.
## Files with dynamic IPs
| File Name | IP |
| ---------- | ---- |
|[Pinniped LoadBalancer](tkg2/pinniped/pinniped.yaml)|Pinniped Load Balancer IP|
|[Pinniped OIDC Provider](tkg2/pinniped/pinniped.yaml)|Pinniped OIDC FQDN|
|[Cert Manager to Contour](tkg2/cert-manager/ingress-certs/cert-manager-egress-public-ip.yaml)| Contour load balancer ips|
|[Falcosidekick](tkg2/falco/falco-ouputs.yaml)| Update ES rule with your logging sytem IP|
|[Grafana](tkg2/grafana/grafana.yaml)| Update fqdns if not using public github for oauth|
|[Core DNS](tkg/core-dns.yaml)|IP of nameserver|
# Defaults - All Clusters
## default-deny
The default deny policy is in the baseline tier and should be applied last. It essentially says to drop all traffic that does not match any of the other network policies. So if egress or ingress traffic in or out of a pod is not explicitly defined it will be blocked. The priority on this policy is 150 which is the maximum supported number for the baseline tier. Non baseline tiers can go up to 50000 at the rule level.

## allow-from-prometheus
The allow from prometheus policy is in the baseline tier and should be applied right before default deny. It essentially says to allow traffic into all pods from the prometheus server in the namespace tanzu-system-monitoring. This is so that prometheus can scrape the metrics endpoints.

## **Important Info on Antrea Gateway**

All external traffic for LoadBalancer and Node IP services with externalTrafficPolicy set to Cluster go through the Antrea Gateway on the Nodes. This means the source ip gets updated. If the externalTrafficPolicy is set to Local then the source ip is kept in tact and rules can be written to only allow traffic from certain external IP's. The default however is Cluster as this is the most efficient and fastest routing mechanism.

Additionally when attempting to reach the apiserver the traffic routes through the antrea gateway as well which requires ingress traffic from the control planes antrea gw ip. If there are multiple control plane nodes all of them will need to added as seperate IPBlocks. This is necessary for all webhooks: cert-manager-webhook, gatekeeper-controller-manager, all pods in capi-webhook-system on mangement clusters, and the metrics-server.

For add on namespaces if they need to be exposed externally every nodes antrea gateway needs to have ingress access. The Ingress Controller needs ingress from all nodes Antrea Gateways as it exposes services external to the kubernetes network. Additionally it was observed that the falcosidekick pods need ingress access from all antrea gateways as this is more of a management namespace and interacts with all of the nodes directly.

## Core Dns

Core dns needs access to function. Ingress traffic should be allowed from all pods within the cluster. This traffic is still blocked at the egress level for all pods. So all this policy does is enables users of the cluster to only need a policy added to their namespace to allow the egress traffic when it is needed. Finally it needs access to the nameserver defined in the /etc/resolv.conf file on the hosts. This ipBlock will need to be updated if the nameserver is not at 10.0.0.2/32. Additionally it needs to allow ingress access thru the antrea gateways.

## Iaas-Metadata
This policy prevents pods from reaching out to the IAAS metadata endpoint. As it is in the emergency layer it can not be overwritten by a user policy. Additionally once TKG supports Antrea 1.3 a 2nd rule will be added to account for the ipv6 URL.

## Kube System Hardening

The kube system hardening policy allows all traffic within kube-system's namespace to communicate freely with other pods in the namespace as well as access from kube-system to all of the worker nodes. 

## Cert Manager
A custom network policy will be needed for any issuers provided an example for acme-staging and acme-prod for letsencrypt have been provided 

[tkg](tkg/cert-manager/clusterissuer/)
[tkg2](tkg2/cert-manager/clusterissuer/)

### cert-manager-apiserver
This allows cert-manager, cainjector, and the webhook to make egress calls to the apiserver to create and track all of the different crds that cert-manager manages such as certificates, challenges, orders, certificate requests, etc. 
### cert-manager-dns
This allows just the cert-manager pod to resolve dns endpoints such as that needed to contact lets encrypt to generate a certificate or to hit the http01 endpoint needed for verification of endpoints.
## http-resolver-envoy
This allows all of the http resolver pods created by cert-manager to receive communications from envoy. This is only needed when the cluster issuer or issuer that is used to generate certificates has an http solver. It is recommended to apply regardless so that you do not have issues down the line with cert-manager.

## Ingress-Certs
This allows egress traffic to the public endpoint of the envoy service running in the tanzu system ingress namespace. The ipBlocks will need to be updated to match the ips behind the loadbalancer. This allows the traffic to go from envoy to your endpoints.


## Tanzu System Ingress
If the tanzu contour ingress add on is installed the files in contour folder are needed for it to function as well as the files in the cert-manager as cert-manager is a prerequisite for the ingress controller. 

[tkg contour](tkg/contour)
[tkg cert-manager](tkg/contour)
[tkg2 contour](tkg2/cert-manager)
[tkg2 cert-manager](tkg2/cert-manager)
### Contour
The contour network policy defines all fo the access that the contour pods need to function. They need access to the kubernetes apiserver to pull all ingress objects as well as ingress rule objects. They need access to egress to core dns to resolve various dns records such as that of the kubernetes apiserver. Finally they need to allow ingress traffic from envoy which is the other pod in the ingress controller that is running in the same namespace.
### envoy
Envoy the other component of contour has one policy that is needed and that is the ability to egress to all pods in the cluster and allow ingress from all nodes antrea gateways for external traffic. The egress all is needed a to talk to contour and so that each time a new ingress rule is defined a network policy does not need to be created in the tanzu-system-ingress namespace to allow the traffic to the new endpoint. This traffic is still blocked by default at the ingress level for all the pods in the cluster and would need to opened with a specific network policy. 

The ingress is needed to allow all external traffic into the gateway. As all of the traffic is routed through the antrea gateway and the source ip is updated due to externalTrafficPolicy = Local this rule allows all external traffic to ingress into envoy.


# Management Clusters
## Tanzu Namespaces
Within the tkg/management folder there are three ClusterNetworkPolicies. One allows egress traffic to all endpoints from all of the tanzu specific namespaces.

## Antrea Gateway 
The 2nd policy allows ingress traffic from the control plane's antrea gateway to the controller manager pods in all of the capi and capa system namespaces.

## allow-iaas-metadata
## Iaas-Metadata
This policy allows pods in capa-system to reach the IAAS metadata endpoint. As it is in the emergency layer it can not be overwritten by a user policy. 

# Additional Applications
The tanzu trust team also recommends installing the following applications on all your clusters. As such all of the following network policies are needed.
## Falco

The default network policies for configuring and setting up falco our FIM management solution have been included. Falco is a CNCF runtime security project and in the falco namespace I install falcosidekick and falcosidekick ui. The falcosidekick is configured to pull the falco events from the host and send them to both the UI as well as elasticsearch. The falcosidekick ui is a web interface that is exposed via ingress. Once all of these network policies are in place you will be able to hit the now publicly accisibly falco sidekick ui that is running within the cluster and all of the events will be streamed to both elastic as well as the ui.
[tkg falco](tkg/falco)
[tkg2 falco](tkg2/falco)

### falco-envoy-ingress
This policy allows the envoy pod to ingress into the sidekick-ui pod that is exposed by the ingress controller as well as to the http-solver pod that gets created by cert-manager as part of the cert creation process.

### falco-outputs
This policy allows falcosidekick pods to egress to the ui pod running in the same namespace as well as to my teams elasticsearch instance. The elasticsearch ipBlock would need to be updated to point at your elastic. This allows falcosidekick to post events to elasticsearch as well as the ui.

### falcosidekick-dns
This policy allows falcosidekick to egress to dns to resolve the elasticsearch url as well as the sidekick-ui url. 

### Antrea Gateway
This policy allows ingress traffic from the antrea gateway on all nodes to the falcosidekick pods. This is due to falco being more of a management namespace and needing to talk directly to all of the nodes. This would not be needed in a normal user namespace. 

## Prometheus

Prometheus is a monitoring and time series database used to monitor kubernetes.

In order for it to run you need to create a network policies.

If you would like to utilize alert manager policies will need to be created to allow access to the system that sends out messages.(smtp, slack, pagerduty, etc.)
### prometheus

Prometheus gathers metrics by scraping endpoints and pulling data in. As such it needs egress all from its pods so that new metric endpoints can be added seemlessly. Alternatively a rule could be written for every metric endpoint and some of them are dynamic as pods spin up and spin down.

Addiontally prometheus metrics are visualized in the dashboarding tool Grafana. As such ingress  needs to be allowed from grafana into the prometheus server.

## Grafana

Grafana is a dashboarding solution that can pull in data from various data sources. The one provided by the tanzu team comes with a default prometheus data source as such the policies provided only allow access to that data source as well as antrea gateways. If you would like to gather metrics from other data sources a policy will need to be created to allow egress to that source.

### grafana

The policy provided allows grafana egress access to the kubernetes api server, dns, and prometheus server kubernetes services. The api server and dns are needed for grafana to function as normal and the prometheus endpoint is needed to pull in metrics from our pre configured data source.

Additionally the example grafana provided by the tanzu team has an example of configuring github auth and accessing charts available on grafana.net so egress rules have been provided to allow access to these fqdn. If you would like to configure a different auth endpoint or remove the ability to pull charts from grafana.net these egress rules can be removed or modified.

## Fluent-Bit

Fluent bit is the recommend log forwarding agent and it is provided via a tanzu package.

### fluent-bit-api-server
The fluent bit example provided by the tanzu trust team only outputs logs to sysout. This policy will need to modified or a new one will need to be created to allow egress to the syslog system that you wish to store logs. 

The default policy does have an egress policy to dns and kubernetes api server kubernetes services. These are needed for fluent bit to start.
## Gatekeeper

Gatekeeper is the recommended pod security tool by the tanzu trust team. It is used in place of the pod security admission controller and pod security policies.

### antrea-gw
As gatekeeper has webhooks ingress access is needed from the antrea gateway in order for antrea to start and operate.

### gatekeeper-system-apiserver
Gatekeeper communicates with the apiserver and kubernetes dns to retireve information on crds it manages. This rule allows egress access to these kubernetes services.

## Pinniped

Pinniped configures oidc access to your kubernetes clusters and allows you to create rbac that ties kubernetes roles and cluster roles to oidc users and groups.

### pinniped

Pinniped supervisor connects with the upstrteam oidc. As such this policy will need to be updated to point at the url of your oidc provider. Additionally the supervisor needs to communicate with the kubernetes api server and to resolve dns names as such an egress rule has been provided that allows access to these kubernetes services. Finally an ingress rule has been added to allow traffic from the antrea gateways in order for pinniped to function properly.

The pinniped conceierge connects with the supervisor via the lb attached to the supervisor service. As such the lb name is dynamic and needs to be udpated in the policy.  Additionally the concierge needs to communicate with the kubernetes api server and to resolve dns names as such an egress rule has been provided that allows access to these kubernetes services. Finally an ingress rule has been added to allow traffic from the antrea gateways in order for pinniped to function properl

For more information on how pinniped works and why these network policies are needed the architecture can be viewed [here](https://pinniped.dev/docs/background/architecture/)




# Deployment

To deploy these network policies simply run:

```sh
kubectl apply -f <path/to/folder>
```

The above command will apply all of the yaml files in the folder but not any children folders.

If you would like to apply the command recursively(including sub folders and all of there yamls) you can do:

```sh
kubectl apply -f <path/to/folder> -R
```