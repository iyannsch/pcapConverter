# CMB Assignment 02 code + notebooks

This is a project for containing code for the second assignment of the Connected Mobility Basics lecture.

## Analysis Code

Under the folder `analysis` you can find jupyter notebook we used for the figure creation for our analysis report.

There are three notebooks:
- `dns_activityandprotocol.ipynb`
- `IdleAnalysisNotebook.ipynb`
- `IPv4_6_encryption_http.ipynb`

## Python Capturing Code

Also in this repository you can find the code we used to capture our traffic data. We used the script `capture.sh` under a 15 min cronjob to create and process the traffic data into json files. The line to add to the crontab is as seen below:

```bash
* * * * * cd [path to repository] && bash ./capture.sh
```

These json files are then used by the jupyter notebooks.
