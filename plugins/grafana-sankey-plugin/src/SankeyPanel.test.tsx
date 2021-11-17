import { configure, shallow } from 'enzyme';
import Adapter from 'enzyme-adapter-react-16';
import { SankeyPanel } from './SankeyPanel';
import { LoadingState, PanelProps, TimeRange } from '@grafana/data';
import React from 'react';
import { Chart } from 'react-google-charts';

configure({ adapter: new Adapter() });

describe('Sankey Diagram test', () => {
  it('should return true', () => {
    expect(true).toBeTruthy();
  });
  it('should render Chart', () => {
    let props = {} as PanelProps;
    let timeRange = {} as TimeRange;
    props.data = {
      series: [],
      state: LoadingState.Done,
      timeRange: timeRange,
    };
    props.width = 600;
    props.height = 600;
    props.options = {};
    let data = [
      ['From', 'To', 'Bytes'],
      ['Source N/A', 'Destination N/A', 1],
    ];
    let component = shallow(<SankeyPanel {...props} />);
    expect(
      component.contains(
        <Chart chartType="Sankey" width={600} height={'600px'} loader={<div>Loading Chart</div>} data={data} />
      )
    ).toEqual(true);
  });
});
