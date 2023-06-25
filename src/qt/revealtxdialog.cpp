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

    setupButtons();
    ui->buttonBox->button(QDialogButtonBox::Reset)->setText("Delete Transaction?");
    connect(ui->buttonBox->button(QDialogButtonBox::Reset), SIGNAL(clicked()), this, SLOT(deleteTransaction()));
}

RevealTxDialog::~RevealTxDialog()
{
    delete ui;
}

struct ButtonInfo
{
    QString name;
    void (RevealTxDialog::*slot)();
};

void RevealTxDialog::setupButtons()
{
    std::vector<ButtonInfo> buttons = {
        {"pushButtonCopyID", &RevealTxDialog::copyID},
        {"pushButtonCopyAddr", &RevealTxDialog::copyAddress},
        {"pushButtonCopyPrivKey", &RevealTxDialog::copyPrivateKey},
        {"pushButtonCopyTxAmount", &RevealTxDialog::copyTxAmount},
        {"pushButtonCopyTxFee", &RevealTxDialog::copyTxFee},
        {"pushButtonCopyTxPaymentID", &RevealTxDialog::copyTxPaymentID},
        {"pushButtonCopyTxRingSize", &RevealTxDialog::copyTxRingSize},
        {"pushButtonOpenTXID", &RevealTxDialog::openTXinExplorer},
        {"pushButtonCopyBlockHash", &RevealTxDialog::copyBlockHash},
        {"pushButtonCopyBlockHeight", &RevealTxDialog::copyBlockHeight},
        {"pushButtonOpenBlock", &RevealTxDialog::openBlockInExplorer},
        {"pushButtonOpenBlock1", &RevealTxDialog::openBlockInExplorer},
    };

    for(const auto& button : buttons)
    {
        QPushButton *pushButton = this->findChild<QPushButton*>(button.name);
        if(pushButton != nullptr)
        {
            pushButton->setStyleSheet("background:transparent;");
            if(button.name == "pushButtonOpenTXID" || button.name == "pushButtonOpenBlock" || button.name == "pushButtonOpenBlock1") {
                pushButton->setIcon(QIcon(":/icons/eye"));
            } else {
                pushButton->setIcon(QIcon(":/icons/editcopy"));
            }
            connect(pushButton, &QPushButton::clicked, this, button.slot);
        }
    }
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

void RevealTxDialog::setTxAmount(CAmount amount)
{
    int nDisplayUnit;
    ui->lblTxAmount->setText(BitcoinUnits::format(nDisplayUnit, amount, false, BitcoinUnits::separatorAlways));
}

void RevealTxDialog::setTxFee(CAmount fee)
{
    int nDisplayUnit;
    ui->lblTxFee->setText(BitcoinUnits::format(nDisplayUnit, fee, false, BitcoinUnits::separatorAlways));
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

void RevealTxDialog::setBlockHeight(int blockHeight)
{
    ui->lblBlockHeight->setText(QString::number(blockHeight));
}

void RevealTxDialog::setBlockHash(QString blockHash)
{
    ui->lblBlockHash->setText(blockHash);
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

void RevealTxDialog::copyBlockHeight(){
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->lblBlockHeight->text());
}

void RevealTxDialog::copyBlockHash(){
    QClipboard *clipboard = QApplication::clipboard();
    clipboard->setText(ui->lblBlockHash->text());
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

void RevealTxDialog::openBlockInExplorer()
{
    QString URL;
    // Adjust link depending on Network
    if (Params().NetworkID() == CBaseChainParams::MAIN) {
        URL = "https://explorer.prcycoin.com/block/";
    } else if (Params().NetworkID() == CBaseChainParams::TESTNET){
        URL = "https://testnet.prcycoin.com/block/";
    }
    QDesktopServices::openUrl(QUrl(URL.append(ui->lblBlockHash->text())));
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
            GUIUtil::showMessageBox(
                tr("Invalid or non-wallet transaction id"),
                tr("Invalid or non-wallet transaction id."),
                QMessageBox::Critical);
            return;
        }
        // Erase it
        if (!pwalletMain->EraseFromWallet(hash)) {
            GUIUtil::showMessageBox(
                tr("Unable to delete transaction id"),
                tr("Unable to delete transaction id."),
                QMessageBox::Critical);
            return;
        }

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
