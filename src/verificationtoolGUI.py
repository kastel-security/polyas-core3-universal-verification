#!/bin/python

# Copyright © 2019-2023, Karlsruhe Institute of Technology (KIT), Maximilian Noppel, Christoph Niederbudde


from PyQt5.QtWidgets import *
from verificationtool import *
import sys

headerStyle = """
QLabel{
    font-size: 20px;
}
"""

resStyle = """
QLabel{
    font-size: 20px;
    text-align: center;
}
"""

logStyle = """
QLabel{
    font-size: 12px;
    text-align: left;
}
"""

def set_tallying_result_GUI(tallying, registry, tallyingTable):
    resulttxt = ""
    row = 0
    lang = languageEdit.text()

    for struc in registry.ballotStructures:
        tallyingTable.setItem(row, 0, QTableWidgetItem("[%s] %s" % (struc.id, struc.title.value(lang))))
        row += 1
        for l in struc.lists:
            if tallyingTable:
                tallyingTable.setItem(row, 1, QTableWidgetItem("["+ l.id + "] " + str(l.title.value(lang)) + ": " + str(l.columnHeaders[0].value(lang))))
                tallyingTable.setItem(row, 3, QTableWidgetItem(str(tallying[struc.id][l.id + "forList"])))
            resulttxt += "\n\t%s: %s  : %d" % (l.title.value(lang), l.columnHeaders[0].value(lang), tallying[struc.id][l.id + "forList"])
            row += 1

            for candidate in l.candidates:
                if tallyingTable:
                    txt = "None"
                    if (len(candidate.columns) > 0):
                        txt = candidate.columns[0].value.value(lang)
                    tallyingTable.setItem(row, 2, QTableWidgetItem("[" + candidate.id + "] - " + str(txt)))
                    tallyingTable.setItem(row, 3, QTableWidgetItem(str(tallying[struc.id][l.id][candidate.id])))
                resulttxt += "\n\t\t%s: %d" % (txt, tallying[struc.id][l.id][candidate.id])
                row += 1

    return resulttxt

def start_verification():
    resLabel.setText('Verifying...')
    optionWidget.setVisible(False)
    btStartVerification.setVisible(False)
    showDetails.setVisible(True)
    showDetails.setChecked(True)
    resetButton.setVisible(True)
    accepted = True
    path = pathEdit.text()

    checking_files(path)
    try:
        checking_files(path)
    except Exception as e:
        resLabel.setText("Provided directory is invalid.")
        return

    registry = load_registry(path)
    s = registry.desc
    headerLabel.setText("Election: %s" % s)

    print_registry(path)
    (tallying, rows) = do_tallying(path)

    # Printing the result
    tallyingTable.setColumnCount(4)
    tallyingTable.setRowCount(rows)

    resulttxt = getTallyingResultCmdLine(tallying, load_registry(path))
    set_tallying_result_GUI(tallying, registry, tallyingTable)

    logger.info(resulttxt)


    # Starting the verification
    accepted = verification(path, accepted, phase1, phase2, phase3, phase4)

    if secondDevice.isChecked():
        accepted &= verify_second_device_public_parameters(path, secondDeviceProgress)
    if receipts.isChecked():
        logTo = []
        accepted &= verify_receipts(path, receiptsProgress, receiptsLog.isChecked(), logTo)
        if receiptsLog.isChecked():
            text = ""
            for t in logTo:
                if t["status"] == ReceiptStatus.MALFORMED:
                    text += "Ballot cast confirmation file %s does not have the correct format.\n" % t["file"]
                elif t["status"] == ReceiptStatus.INVALID:
                    text += "Ballot cast confirmation file %s does not contain a valid signature.\n" % t["file"]
                elif t["status"] == ReceiptStatus.MISSING:
                    text += "Ballot %s is not included in the ballot box.\n" % t["fingerprint"]
                elif t["status"] == ReceiptStatus.PRESENT:
                    text += "Ballot %s is included in the ballot box with status %s.\n" % (t["fingerprint"], t["ballotStatus"].name)
            receiptsLogLabel.setText(text)
            receiptsLogArea.setWidget(receiptsLogLabel)
            receiptsLogArea.setVisible(True)

    if accepted:
        resLabel.setText('Accepted!')
    else:
        resLabel.setText('Not accepted!')

def setGUIExtras(checkbox, receiptWidgets: list):
    for widget in receiptWidgets:
        widget.setVisible(checkbox.isChecked())

def resetProgress():
    phase1.setValue(0)
    phase2.setValue(0)
    phase3.setValue(0)
    phase4.setValue(0)
    secondDeviceProgress.setValue(0)
    receiptsProgress.setValue(0)
    phase1.setStyleSheet(greenStyle)
    phase2.setStyleSheet(greenStyle)
    phase3.setStyleSheet(greenStyle)
    phase4.setStyleSheet(greenStyle)
    secondDeviceProgress.setStyleSheet(greenStyle)
    receiptsProgress.setStyleSheet(greenStyle)

def reset():
    optionWidget.setVisible(True)
    progressWidget.setVisible(True)
    showDetails.setVisible(False)
    btStartVerification.setVisible(True)
    resetButton.setVisible(False)
    receiptsLogLabel.setText("")
    receiptsLogArea.setVisible(False)
    tallyingTable.setRowCount(0)
    tallyingTable.setColumnCount(0)
    resLabel.setText("")
    resetProgress()

def browse():
    filepath = QFileDialog.getExistingDirectory()
    pathEdit.setText(filepath)

# QtApplication
app = QApplication([])
window = QWidget()
layout = QVBoxLayout()

headerLabel = QLabel("")
layout.addWidget(headerLabel)

optionWidget = QGroupBox()
optionLayout = QGridLayout()
optionWidget.setLayout(optionLayout)
#Selection of additional verification tasks
#Second device public parameters
secondDevice = QCheckBox(text="Verify second device public parameters")

secondDeviceLabel = QLabel("Verifying the second device public parameters")
secondDeviceProgress = QProgressBar()
secondDeviceLabel.setVisible(False)
secondDeviceProgress.setVisible(False)

secondDevice.stateChanged.connect(lambda: setGUIExtras(secondDevice, [secondDeviceLabel, secondDeviceProgress]))
optionLayout.addWidget(secondDevice, 0, 0)

#Ballot cast confirmations
receipts = QCheckBox(text="Verify ballot cast confirmations")
receiptsLog = QCheckBox(text="Show status of ballot cast confirmation")
receiptsLogArea = QScrollArea()
receiptsLogArea.setVisible(False)
receiptsLogLabel = QLabel()

receiptsLabel = QLabel("Verifying the ballot cast confirmations")
receiptsProgress = QProgressBar()
receiptsLabel.setVisible(False)
receiptsProgress.setVisible(False)

receipts.stateChanged.connect(lambda: setGUIExtras(receipts, [receiptsLog, receiptsLabel, receiptsProgress]))
receiptsLog.setVisible(False)
optionLayout.addWidget(receipts, 1, 0)
optionLayout.addWidget(receiptsLog, 2, 0)

pathEdit = QLineEdit('enter path to election files')
pathDialog = QPushButton("browse...")
pathDialog.clicked.connect(browse)
optionLayout.addWidget(pathEdit, 3, 0)
optionLayout.addWidget(pathDialog, 3, 1)

languageEdit = QLineEdit('enter language')
optionLayout.addWidget(languageEdit, 4, 0)

layout.addWidget(optionWidget)

# Progress bars
progressWidget = QGroupBox()
progressLayout = QVBoxLayout()
progressWidget.setLayout(progressLayout)

# Phase 1
phase1Label = QLabel("Verifying the public election key with zk-proof")
progressLayout.addWidget(phase1Label)
phase1 = QProgressBar()
progressLayout.addWidget(phase1)

# Phase 2
phase2Label = QLabel("Verifying ballot-box")
progressLayout.addWidget(phase2Label)
phase2 = QProgressBar()
progressLayout.addWidget(phase2)

# Phase 3
phase3Label = QLabel("Verifying ballot decryption")
progressLayout.addWidget(phase3Label)
phase3 = QProgressBar()
progressLayout.addWidget(phase3)

# Phase 4
phase4Label = QLabel("Verifying shuffle")
progressLayout.addWidget(phase4Label)
phase4 = QProgressBar()
progressLayout.addWidget(phase4)

#Adding optional progres bars
progressLayout.addWidget(secondDeviceLabel)
progressLayout.addWidget(secondDeviceProgress)
progressLayout.addWidget(receiptsLabel)
progressLayout.addWidget(receiptsProgress)

layout.addWidget(progressWidget)

# Result Label
lb = QLabel("Result:")
layout.addWidget(lb)
resLabel = QLabel("")
layout.addWidget(resLabel)

showDetails = QCheckBox(text="Show details")
showDetails.stateChanged.connect(lambda: setGUIExtras(showDetails, [progressWidget]))
showDetails.setChecked(True)
showDetails.setVisible(False)
layout.addWidget(showDetails)

tallyingTable = QTableWidget()
layout.addWidget(tallyingTable)

# Scrollable log area for ballot cast confirmation
layout.addWidget(receiptsLogArea)

resetProgress()

headerLabel.setStyleSheet(headerStyle)
resLabel.setStyleSheet(resStyle)
receiptsLogLabel.setStyleSheet(logStyle)

btStartVerification = QPushButton('Start verification')
btStartVerification.clicked.connect(start_verification)
layout.addWidget(btStartVerification)

resetButton = QPushButton('New verification')
resetButton.clicked.connect(reset)
resetButton.setVisible(False)
layout.addWidget(resetButton)


window.setLayout(layout)
window.setWindowTitle('Verification of election result')
window.setFixedSize(800,800)
window.show()

if __name__ == '__main__':
    sys.exit(app.exec_() )


