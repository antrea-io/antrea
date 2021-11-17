import React from 'react';
import { PanelProps } from '@grafana/data';
import { SankeyOptions } from 'types';
import Chart from 'react-google-charts';

interface Props extends PanelProps<SankeyOptions> {}

export const SankeyPanel: React.FC<Props> = ({ options, data, width, height }) => {
  let result = [['From', 'To', 'Bytes']];
  let n = data.series.length;
  for (let i = 0; i < n; i++) {
    let record = data.series[i].name?.split(',');
    let source = record![0];
    let destination = record![1];
    if (destination === '') {
      destination = record![2];
    }
    let value = data.series[i].fields[1].state as any;
    let stats = value.calcs as any;
    result.push([source, destination, stats.sum]);
  }
  return (
    <div>
      <Chart width={600} height={'600px'} chartType="Sankey" loader={<div>Loading Chart</div>} data={result} />
    </div>
  );
};
