# Antrea Adopters

<a href="http://glasnostic.com" border="0" target="_blank">
<img alt="glasnostic.com" src="docs/assets/adopters/glasnostic-logo.png"
height="50"></a>&nbsp; &nbsp; &nbsp;

<a href="https://www.transwarp.io" border="0" target="_blank">
<img alt="https://www.transwarp.io" src="docs/assets/adopters/transwarp-logo.png"
height="50"></a>&nbsp; &nbsp; &nbsp;

<a href="https://www.terasky.com" border="0" target="_blank">
<img alt="https://www.terasky.com" src="docs/assets/adopters/terasky-logo.png"
height="50"></a>&nbsp; &nbsp; &nbsp;

## Success Stories

Below is a list of adopters of Antrea that have publicly shared the details
of how they use it.

**[Glasnostic](https://glasnostic.com)**

Glasnostic makes modern cloud operations resilient. It does this by shaping how
systems interact, automatically and in real-time. As a result, DevOps and SRE
teams can deploy reliably, prevent failure and assure the customer experience.
We use Antrea's Open vSwitch support to tune how services interact in Kubernetes
clusters. We are @glasnostic on Twitter.

**[Transwarp](https://www.transwarp.io)**

Transwarp is committed to building enterprise-level big data infrastructure
software, providing enterprises with infrastructure software and supporting
around the whole data lifecycle to build a data world of the future.

1. We use Antrea's AntreaClusterNetworkPolicy and AntreaNetworkPolicy to protect
big data software for every tenant of our kubernetes platform.
2. We use Antrea's Open vSwitch to support Pod-To-Pod network between flannel and
antrea clusters, and also between antrea clusters
3. We use Antrea's Open vSwitch to support Pod-To-Pod network between flannel and
antrea nodes in one cluster for upgrading.
4. We use Antrea's Egress feature to keep the original source ip to ensure
Internal Pods can get the real source IP of the request.

You can contact us with <mkt@transwarp.io>

**[TeraSky](https://terasky.com)**

TeraSky is a Global Advanced Technology Solutions Provider.
Antrea is used in our internal Kubernetes clusters as well as by many of our customers.
Antrea helps us to apply a very strong and flexible security models in Kubernetes.
We are very heavily utilizing Antrea Cluster Network Policies, Antrea Network Policies,
and the Egress functionality.

We are @TeraSkycom1 on Twitter.  

## Adding yourself as an Adopter

It would be great to have your success story and logo on our list of
Antrea adopters!

To add yourself, you can follow the steps outlined below, alternatively,
feel free to reach out via Slack or on Github to have our team
add your success story and logo.

1. Prepare your addition and PR as described in the Antrea
[Contributor Guide](CONTRIBUTING.md).

2. Add your name to the success stories, using **bold** format with a link to
your web site like this: `**[Example](https://example.com)**`

3. Below your name, describe your organization or yourself and how you make
use of Antrea. Optionally, list the features of Antrea you are using. Please
keep the line width at 80 characters maximum, and avoid trailing spaces.

4. If you are willing to share contact details, e.g. your Twitter handle, etc.
add a line where people can find you.

    Example:

    ```markdown
    **[Example](https://example.com)**
    Example.com is a company operating internationally, focusing on creating
    documentation examples. We are using Antrea in our K8s clusters deployed
    using Kubeadm. We making use of Antrea's Network Policy capabilities.
    You can reach us on twitter @vmwopensource.
    ```

5. (Optional) To add your logo, simply drop your logo in PNG or SVG format with
a maximum size of 50KB to the [adopters](docs/assets/adopters) directory.
Name the image file something that reflects your company (e.g., if your company
is called Acme, name the image acme-logo.png). Then add an inline html link
directly bellow the [Antrea Adopters section](#antrea-adopters). Use the
following format:

    ```html
    <a href="http://example.com" border="0" target="_blank">
    <img alt="example.com" src="docs/assets/adopters/example-logo.png"
    height="50"></a>&nbsp; &nbsp; &nbsp;
    ```

6. Send a PR with your addition as described in the Antrea
[Contributor Guide](CONTRIBUTING.md)

## Adding a logo to Antrea.io

We are working on adding an *Adopters* section on [antrea.io][1].
Follow the steps above to add your organization to the list of Antrea Adopters.
We will follow up and publish it to the [antrea.io][1] website.

[1]: https://antrea.io
