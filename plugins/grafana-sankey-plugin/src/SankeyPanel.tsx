import React from 'react';
import { PanelProps } from '@grafana/data';
import { SankeyOptions } from 'types';
import Chart from 'react-google-charts';

interface Props extends PanelProps<SankeyOptions> {}

export const SankeyPanel: React.FC<Props> = ({ options, data, width, height }) => {
  let result = [
    ['From', 'To', 'Bytes'],
    ['Source N/A', 'Destination N/A', 1],
  ];
  let sources = data.series
    .map((series) => series.fields.find((field) => field.name === 'source'))
    .map((field) => {
      let record = field?.values as any;
      return record?.buffer;
    })[0];
  if (sources !== undefined) {
    let destinations = data.series
      .map((series) => series.fields.find((field) => field.name === 'destination'))
      .map((field) => {
        let record = field?.values as any;
        return record?.buffer;
      })[0];
    let destinationIPs = data.series
      .map((series) => series.fields.find((field) => field.name === 'destinationIP'))
      .map((field) => {
        let record = field?.values as any;
        return record?.buffer;
      })[0];
    let bytes = data.series
      .map((series) => series.fields.find((field) => field.name === 'bytes'))
      .map((field) => {
        let record = field?.values as any;
        return record?.buffer;
      })[0];
    let n = sources.length;
    for (let i = 0; i < n; i++) {
      if (bytes[i] === 0) {
        continue;
      }
      let record = [];
      let source = sources[i];
      let destination = destinations[i];
      if (source === '') {
        source = 'N/A';
      }
      if (destination === '') {
        if (destinationIPs[i] === '') {
          destination = 'N/A';
        } else {
          destination = destinationIPs[i];
        }
      } else {
        // Google Chart will not be rendered if source is equal to destination.
        // Add an extra space to differentiate to-self traffic (e.g. intra-Node).
        if (source === destination) {
          destination = destination + ' ';
        }
      }
      record.push(source);
      record.push(destination);
      record.push(bytes[i]);
      if (i === 0) {
        result = [['From', 'To', 'Bytes']];
      }
      result.push(record);
    }
  }
  return (
    <div>
      <Chart width={600} height={'600px'} chartType="Sankey" loader={<div>Loading Chart</div>} data={result} />
    </div>
  );
};
