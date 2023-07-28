# Polyas-Checker

Polyas-Checker is a tool to verify the public boards of the polyas voting systems for universal verifiability

## Requirements
```bash
python3(https://www.python.org/downloads/)
gnupg(https://gnupg.org/download/) is required only if ballot revocation is supported and revocation tokens require signing
```

## Installation using anaconda

### Setup environment

```bash
conda env create --name verificationtool --file environment.yml
```

### Activating environment
```bash
Before executing the tool or unittests, run
conda activate verificationtool
```

## Installation using pip

### Dependencies

```bash
python -m pip install -r requirements.txt
```


## Executing
### Executing the tool in command line
```bash
python src/verificationtool.py [-s | --second-device] [-r | --receipt] [--log] [-l | --language lang] src
src: Absolute path to election files
-s, --second-device: Check second device public parameters in file src/second-device-public-parameters.json
-r, --receipt: Check ballot cast confirmation files (receipts) in src/receipts
--log: Log the status of ballots for all checked ballot cast confirmations
-l, --language: Sets the preferred language. Texts that are available will be displayed in the preferred language, other texts will be displayed in the default language

```

### Executing the GUI
Additionally, this repository contains a GUI tool based on Qt5.

```bash
python src/verificationtoolGUI.py
```
The path to the election files as well as all other options are entered in the GUI

## Unittest
```bash
python -m unittest discover src
```

## Contribution
See [CONTRIBUTION](CONTRIBUTION)

## Licence
See [LICENSE](LICENSE)
