# ebpf as a SRE datasource with Reliably

This repository contains the code of my lightning talk at the ebpf 2021
conference. It is made of a very basic ebpf program that simply discards
anything non TCP packets on an interface we attach to. At the application
level we filter any packet not going or coming from a target port we
are interested in. We then use this data to measure latency and error rates
of requests/response to said server. The server is intended to return
errors from time to time.

We are prototyping how SRE can directly benefit from ebpf events to gain
visibility over their system. By transforming these events into indicators
to publish to service level objects.

## Requirements

* a recent Linux kernel (> 5.10)
* Python 3.8+
* BCC and BCC python for your system installed. Indeed the Python package
  for BCC is not pip-installable so make you install with your system
  package manager. On Ubuntu for example: `sudo apt install bpfcc python3-bpfcc`
* A virtual environment:
  ```
  $ python3 -m venv --system-site-packages .venv
  ```
* Python dependencies:
  ```
  $ ./.venv/bin/pip install -r requirements.txt
  ```
* An authenticated [Reliably](https://reliably.com/docs/getting-started/) CLI
* The [hey](https://github.com/rakyll/hey) load test program

## Running

Once you have installed all the dependencies and authenticated against
Reliably, run the following commands.

* The application server:

  ```
  $ ./.venv/bin/uvicorn --port=8000 server:app 
  ```

* The `hey` program to induce some mild load on the server:

  ```
  $ hey -c 3 -q 10 -z 600s http://localhost:8000/
  ```

* The reliably's CLI. Run first the following
  `$ reliably slo sync -m reliably.yaml`. This needs to be run only once.
  Then run this command to watch your SLO:

  ```
  $ reliably slo report -m reliably.yaml -w
  ```

* The ebpf program:

  ```
  $ sudo .venv/bin/python3 script.py --reliably-config $HOME/.config/reliably/config.yaml
  ```

  This must run as root.

Once this is done, watch your SLO changing dependning on how the server
replies.
