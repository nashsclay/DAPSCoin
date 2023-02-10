#include "revealtxdialog.h"
#include "ui_revealtxdialog.h"
#include "bitcoinunits.h"
#include "chainparams.h"
#include "guiutil.h"
#include "wallet/wallet.h"

#include <QClipboard>
#include <QDesktopServices>
#include <QKeyEvent>
#include <QPushButton>
#include <QUrl>

RevealTxDialog::RevealTxDialog(QWidget *parent) :
    QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
    ui(new Ui::RevealTxDialog)
{
    ui->setupUi(this);

    ui->pushButtonCopyID->setStyleSheet("background:transparent;");
    ui->pushButtonCopyID->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->pushButtonCopyID, SIGNAL(clicked()), this, SLOT(copyID()));

    ui->pushButtonCopyAddr->setStyleSheet("background:transparent;");
    ui->pushButtonCopyAddr->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->pushButtonCopyAddr, SIGNAL(clicked()), this, SLOT(copyAddress()));

    ui->pushButtonCopyPrivKey->setStyleSheet("background:transparent;");
    ui->pushButtonCopyPrivKey->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->pushButtonCopyPrivKey, SIGNAL(clicked()), this, SLOT(copyPrivateKey()));

    ui->pushButtonCopyTxAmount->setStyleSheet("background:transparent;");
    ui->pushButtonCopyTxAmount->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->pushButtonCopyTxAmount, SIGNAL(clicked()), this, SLOT(copyTxAmount()));

    ui->pushButtonCopyTxFee->setStyleSheet("background:transparent;");
    ui->pushButtonCopyTxFee->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->pushButtonCopyTxFee, SIGNAL(clicked()), this, SLOT(copyTxFee()));

    ui->pushButtonCopyTxPaymentID->setStyleSheet("background:transparent;");
    ui->pushButtonCopyTxPaymentID->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->pushButtonCopyTxPaymentID, SIGNAL(clicked()), this, SLOT(copyTxPaymentID()));

    ui->pushButtonCopyTxRingSize->setStyleSheet("background:transparent;");
    ui->pushButtonCopyTxRingSize->setIcon(QIcon(":/icons/editcopy"));
    connect(ui->pushButtonCopyTxRingSize, SIGNAL(clicked()), this, SLOT(copyTxRingSize()));

    ui->pushButtonOpenTXID->setStyleSheet("background:transparent;");
    ui->pushButtonOpenTXID->setIcon(QIcon(":/icons/eye"));
    connect(ui->pushButtonOpenTXID, SIGNAL(clicked()), this, SLOT(openTXinExplorer()));

    ui->buttonBox->button(QDialogButtonBox::Reset)->setText("Delete Transaction?");
    connect(ui->buttonBox->button(QDialogButtonBox::Reset), SIGNAL(clicked()), this, SLOT(deleteTransaction()));
}

RevealTxDialog::~RevealTxDialog()
{
    delete ui;
}

void RevealTxDialog::setTxID(QString strId) 
{
    ui->lblTxID->setText(strId);
}

void RevealTxDialog::setTxAddress(QString strAddr) 
{
    ui->lblAddress->setText(strAddr);
}

void RevealTxDialog::setTxPrivKey(QString strPrivKey) 
{
    ui->lblPrivateKey->setText(strPrivKey);
}

void RevealTxDialog::setTxAmount(QString amount)
{
    int nDisplayUnit;
    ui->lblTxAmount->setText(amount.append(" PRCY"));
}

void RevealTxDialog::setTxFee(CAmount fee)
{
    int nDisplayUnit;
    ui->lblTxFee->setText(BitcoinUnits::formatHtmlWithUnit(0, fee, false, BitcoinUnits::separatorAlways));
}

void RevealTxDialog::setTxPaymentID(uint64_t paymentID)
{
    if (paymentID == 0) {
        ui->pushButtonCopyTxPaymentID->hide();
        ui->label_7->hide();
        ui->lblTxPaymentID->hide();
    }
    ui->lblTxPaymentID->setText(QString::number(paymentID));
}

void RevealTxDialog::setTxRingSize(int64_t ringSize)
{
    ui->lblTxRingSize->setText(QString::number(ringSize));
}

void RevealTxDialog::on_buttonBox_accepted()
{
    //We currently don't do anything on accept
}

void RevealTxDialog::copyID(){
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->lblTxID->text());
}

void RevealTxDialog::copyAddress(){
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->lblAddress->text());
}

void RevealTxDialog::copyPrivateKey(){
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->lblPrivateKey->text());
}

void RevealTxDialog::copyTxAmount(){
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->lblTxAmount->text());
}

void RevealTxDialog::copyTxFee(){
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->lblTxFee->text());
}

void RevealTxDialog::copyTxPaymentID(){
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->lblTxPaymentID->text());
}

void RevealTxDialog::copyTxRingSize(){
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->lblTxRingSize->text());
}

void RevealTxDialog::openTXinExplorer()
{
    QString URL;
    // Adjust link depending on Network
    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        URL = "https://explorer.prcycoin.com/tx/";
    } else if (Params().NetworkID() == CBaseChainParams::TESTNET){
        URL = "https://testnet.prcycoin.com/tx/";
    }
    QDesktopServices::openUrl(QUrl(URL.append(ui->lblTxID->text())));
}

void RevealTxDialog::deleteTransaction()
{
    bool hideSuccess = settings.value("fHideDeleteSuccess", false).toBool();

    QMessageBox::StandardButton reply;
    reply = QMessageBox::question(this, tr("Are You Sure?"),
                                  tr("Are you sure you would like to delete this transaction from the local wallet?\n\nNote: They can only be restored from backup or rescan."),
                                  QMessageBox::Yes|QMessageBox::No);
    if (reply == QMessageBox::Yes) {
        // If it might be a Masternode collateral by value, double check
        if (ui->lblTxAmount->text() == "5000.00000000 PRCY") {
            QMessageBox::StandardButton doubleCheck;
            doubleCheck = QMessageBox::question(this, tr("Potential Masternode Collateral Detected!"),
                                                tr("Potential Masternode Collateral Detected!\nAre you sure?\n\nNote: They can only be restored from backup or rescan."),
                                                QMessageBox::Yes|QMessageBox::No);
            if (doubleCheck == QMessageBox::No) {
                return;
            }
        }

        // Get the hash from the TXID
        uint256 hash;
        hash.SetHex(ui->lblTxID->text().toStdString().c_str());

        // Check it exists
        if (!pwalletMain->mapWallet.count(hash)) {
            QMessageBox msgBox;
            msgBox.setWindowTitle(tr("Invalid or non-wallet transaction id"));
            msgBox.setIcon(QMessageBox::Critical);
            msgBox.setText(tr("Invalid or non-wallet transaction id."));
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.exec();
            return;
        }
        // Erase it
        pwalletMain->EraseFromWallet(hash);

        // Display Success! dialog if not disabled
        QMessageBox msgBox;
        QCheckBox *cb = new QCheckBox(tr("Do not show successful confirmation again"));
        QPushButton *okButton = msgBox.addButton(tr("OK"), QMessageBox::ActionRole);
        msgBox.setCheckBox(cb);

        if (!hideSuccess) {
            msgBox.setWindowTitle(tr("Success!"));
            msgBox.setIcon(QMessageBox::Information);
            msgBox.setText(tr("Transaction ID successfully deleted."));
            msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
            msgBox.exec();
            if (msgBox.clickedButton() == okButton) {
                if (cb->isChecked()) {
                    settings.setValue("fHideDeleteSuccess", true);
                } else {
                    settings.setValue("fHideDeleteSuccess", false);
                }
            }
        }
        accept();
    } else {
        return;
    }
}

void RevealTxDialog::keyPressEvent(QKeyEvent* event)
{
    if (event->key() == Qt::Key_Backspace || event->key() == Qt::Key_Delete) { // press backspace/delete -> delete transaction
        event->ignore();
        deleteTransaction();
    } else if (event->key() == Qt::Key_Escape) { // press escape -> reject
        event->ignore();
        reject();
    } else if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) { // press enter/return -> accept
        event->ignore();
        accept();
    }
}
