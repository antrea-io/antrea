import { PanelPlugin } from '@grafana/data';
import { SankeyOptions } from './types';
import { SankeyPanel } from './SankeyPanel';

export const plugin = new PanelPlugin<SankeyOptions>(SankeyPanel).setPanelOptions((builder) => builder);
