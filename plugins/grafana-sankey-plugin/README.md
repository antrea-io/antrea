# Grafana Sankey Plugin

## What is Grafana Sankey Panel Plugin?

Grafana Sankey Panel Plugin enables users to create Sankey Diagram panel in Grafana
Dashboards. Panels are the building blocks of Grafana. They allow you to visualize
data in different ways. For more information about panels, refer to the documentation
on [Panels](https://grafana.com/docs/grafana/latest/features/panels/panels/). An example
of Sankey Panel Plugin:

<img src="https://downloads.antrea.io/static/02232022/sankey-panel-example.png" width="900" alt="Sankey Panel Plugin Example">

## Acknowledgements

The Sankey Plugin is created using the [Google Chart](https://developers.google.com/chart/interactive/docs/gallery/sankey).

## Data Source

Supported Databases:

- Clickhouse

## Queries Convention

Currently the Sankey Plugin is created for restricted uses, only for visualizing
network flows between the source and destination. To correctly loading data for
the Sankey Plugin, the query must at least return 3 fields, in arbitrary order.

- field 1: the metric value field with an alias of `bytes`
- field 2: value to group by with name or an alias of `source`
- field 3: value to group by with name or an alias of `destination`
- field 4+(optional): value to group by with name or an alias of `destinationIP`

Clickhouse query example:

```sql
select SUM(octetDeltaCount) as bytes, sourcePodName as source, destinationPodName as destination, destinationIP
From flows
GROUP BY source, destination, destinationIP
```

## Installation

### 1. Install the Panel

Installing on a local Grafana:

For local instances, plugins are installed and updated via a simple CLI command.
Use the grafana-cli tool to install sankey-panel-plugin from the commandline:

```shell
grafana-cli --pluginUrl https://downloads.antrea.io/artifacts/grafana-custom-plugins/grafana-sankey-plugin-1.0.0.zip plugins install antreaflowvisibility-grafana-sankey-plugin
```

The plugin will be installed into your grafana plugins directory; the default is
`/var/lib/grafana/plugins`. More information on the [cli tool](https://grafana.com/docs/grafana/latest/administration/cli/#plugins-commands).

Alternatively, you can manually download the .zip file and unpack it into your grafana
plugins directory.

[Download](https://downloads.antrea.io/artifacts/grafana-custom-plugins/grafana-sankey-plugin-1.0.0.zip)

Installing to a Grafana deployed on Kubernetes:

In Grafana deployment manifest, configure the environment variable `GF_INSTALL_PLUGINS`
as below:

```yaml
env:
- name: GF_INSTALL_PLUGINS
   value: "https://downloads.antrea.io/artifacts/grafana-custom-plugins/grafana-sankey-plugin-1.0.0.zip;antreaflowvisibility-grafana-sankey-plugin"
```

### 2. Add the Panel to a Dashboard

Installed panels are available immediately in the Dashboards section in your Grafana
main menu, and can be added like any other core panel in Grafana. To see a list of
installed panels, click the Plugins item in the main menu. Both core panels and
installed panels will appear. For more information, visit the docs on [Grafana plugin installation](https://grafana.com/docs/grafana/latest/plugins/installation/).

## Customization

This plugin is built with [@grafana/toolkit](https://www.npmjs.com/package/@grafana/toolkit), which is a CLI that enables efficient development of Grafana plugins. To customize the plugin and do local testings:

1. Install dependencies

   ```bash
   cd grafana-sankey-plugin
   yarn install
   ```

2. Build plugin in development mode or run in watch mode

   ```bash
   yarn dev
   ```

   or

   ```bash
   yarn watch
   ```

3. Build plugin in production mode

   ```bash
   yarn build
   ```

## Learn more

- [Build a panel plugin tutorial](https://grafana.com/tutorials/build-a-panel-plugin)
- [Grafana documentation](https://grafana.com/docs/)
- [Grafana Tutorials](https://grafana.com/tutorials/) - Grafana Tutorials are step-by-step
guides that help you make the most of Grafana
- [Grafana UI Library](https://developers.grafana.com/ui) - UI components to help you build interfaces using Grafana Design System
