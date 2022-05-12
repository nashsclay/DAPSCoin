#include "revealtxdialog.h"
#include "ui_revealtxdialog.h"
#include "bitcoinunits.h"
#include "chainparams.h"

#include <QClipboard>
#include <QDesktopServices>
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
