# Analysis Notebooks

The notebook in this directory is checked into the repo directly and is self-contained.
It keeps the plotting code inside the notebook so the analysis is easy to read and tweak in one place.

Current notebook:

- `analysis.ipynb`

To open them locally:

```bash
python3 -m pip install --user notebook ipykernel
jupyter notebook notebooks/
```

Notes:

- the notebook defaults to `results/`;
- the batch report path is `make experiment-report`, which now covers all non-warmup runs under `results/`;
- it covers aggregate plots, timing, operational impact, representative-run timelines, detector-event forensics, PCAP views, and extra thesis-style summary charts;
- the markdown cells explain what each plot is meant to show before the chart appears;
- the PCAP sections use `tshark` for packet tables and protocol summaries;
- the notebook also prints a ready-to-run `wireshark` command for the selected capture file.
