# Polyas-Checker

Polyas-Checker is a tool to verify the bulletin boards of the [POLYAS](https://www.polyas.com/) 3.0 E-Voting System for [universal verifiability](https://gi.de/wahlen/verifikation-der-gi-wahlen-tools-gesucht), see also the original [publication](https://publikationen.bibliothek.kit.edu/1000117999).
The POLYAS 3.0 E-Voting System is used in the [elections for the executive and the managing committee](https://gi.de/wahlen/) of the [German Informatics Society](https://gi.de/) in autumn 2023.

## Requirements
* [python3](https://www.python.org/downloads/)
* [gnupg](https://gnupg.org/download/) only if ballot revocation is supported and revocation tokens require signing

## Installation Using [Anaconda](https://www.anaconda.com/)

### Setup Environment
```bash
conda env create --name verificationtool --file environment.yml
```

### Activating Environment
Before executing the tool or unittests, run the following:
```bash
conda activate verificationtool
```

## Installation Using [pip](https://pip.pypa.io)

### Dependencies
```bash
python -m pip install -r requirements.txt
```

## Running Polyas-Checker
### In the Command Line
```bash
python src/verificationtool.py [-s | --second-device] [-r | --receipt] [--log] [-l | --language lang] src
```
* ``src``: Absolute path to election files
* ``-s, --second-device``: Check second device public parameters in file ``src/second-device-public-parameters.json``
* ``-r, --receipt``: Check ballot cast confirmation files (receipts) in ``src/receipts``
* ``--log``: Log the status of ballots for all checked ballot cast confirmations
* ``-l, --language``: Sets the preferred language. If available, texts will be displayed in the preferred language, otherwise in the default language.

### In the GUI
Additionally, this repository contains a GUI tool based on [Qt5](https://github.com/qt/qt5).

```bash
python src/verificationtoolGUI.py
```
The path to the election files as well as all other options are then entered in the GUI.

## Unit Tests
```bash
python -m unittest discover src
```
## Licence
See [LICENSE](LICENSE)

## Contributors
The principal development of this software has been done by [Maximilian Noppel](https://intellisec.de/team/max/) for the 2019 version with major refactorings and extensions for the 2023 version by [Christoph Niederbudde](mailto:udqps@student.kit.edu).

## Contact
For more information, please contact [Michael Kirsten](https://formal.kastel.kit.edu/~kirsten/?lang=en).
