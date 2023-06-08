// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "receivecoinsdialog.h"
#include "ui_receivecoinsdialog.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "optionsmodel.h"
#include "receiverequestdialog.h"
#include "walletmodel.h"

#include <QAction>
#include <QClipboard>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QStylePainter>
#include <QDesktopWidget>
#include <QInputDialog>

ReceiveCoinsDialog::ReceiveCoinsDialog(QWidget* parent) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                                          ui(new Ui::ReceiveCoinsDialog),
                                                          // m_SizeGrip(this),
                                                          model(0)
{
    ui->setupUi(this);


    // context menu actions
    QAction* copyLabelAction = new QAction(tr("Copy label"), this);
    QAction* copyMessageAction = new QAction(tr("Copy message"), this);
    QAction* copyAmountAction = new QAction(tr("Copy amount"), this);
    QAction* copyAddressAction = new QAction(tr("Copy address"), this);

    // context menu
    contextMenu = new QMenu(this);
    contextMenu->setAttribute(Qt::WA_DeleteOnClose);
    contextMenu->addAction(copyLabelAction);
    contextMenu->addAction(copyMessageAction);
    contextMenu->addAction(copyAmountAction);
    contextMenu->addAction(copyAddressAction);

    // Show privacy account address
    ui->lineEditAddress->setStyleSheet("border:none; background: transparent; text-align:center;");
    ui->pushButtonCP->setStyleSheet("background:transparent;");
    ui->pushButtonCP->setIcon(QIcon(":/icons/editcopy"));
    ui->pushButtonGenerate->setIcon(QIcon(":/icons/add"));
    ui->pushButtonGenerate->setStyleSheet("background:transparent;");
    ui->pushButtonRemove->setIcon(QIcon(":/icons/remove"));
    ui->pushButtonRemove->setStyleSheet("background:transparent;");
    connect(ui->pushButtonCP, SIGNAL(clicked()), this, SLOT(copyAddress()));
    connect(ui->pushButtonGenerate, SIGNAL(clicked()), this, SLOT(generateAddress()));
    connect(ui->pushButtonRemove, SIGNAL(clicked()), this, SLOT(removeAddress()));
    connect(ui->reqAddress, SIGNAL(currentIndexChanged(int)), this, SLOT(changeAddress(int)));

    //Create privacy account (wallet is unlocked first launch so !pwalletMain->IsLocked() works here)
    if (pwalletMain && !pwalletMain->IsLocked()) {
        CPubKey temp;
        pwalletMain->GetKeyFromPool(temp);
        pwalletMain->CreatePrivacyAccount();
     }

    QLocale lo(QLocale::C);
    lo.setNumberOptions(QLocale::RejectGroupSeparator);
    QDoubleValidator *dblVal = new QDoubleValidator(0, MAX_MONEY_OUT, 8, ui->reqAmount);
    dblVal->setNotation(QDoubleValidator::StandardNotation);
    dblVal->setLocale(lo);
    ui->reqAmount->setValidator(dblVal);
}

static inline int64_t roundint64(double d)
{
    return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
}

CAmount ReceiveCoinsDialog::getValidatedAmount() {
    double dAmount = ui->reqAmount->text().toDouble();
    CAmount nAmount = roundint64(dAmount * COIN);
    return nAmount;
}

void ReceiveCoinsDialog::setModel(WalletModel* model)
{
    this->model = model;

    if (model && model->getOptionsModel()) {
        connect(model->getOptionsModel(), SIGNAL(displayUnitChanged(int)), this, SLOT(updateDisplayUnit()));
        updateDisplayUnit();
        loadAccount();
    }
}

void ReceiveCoinsDialog::loadAccount()
{
    QRect rec = QApplication::desktop()->availableGeometry();
    int screenWidth = rec.width();
    QString addr;
    std::string address;
    pwalletMain->ComputeStealthPublicAddress("masteraccount", address);

    if (screenWidth <= 1280) {
        //(truncated for screen with less availableGeometry than 1280px)
        addr = "Master Account - " + QString(address.substr(0, 30).c_str()) + "..." + QString(address.substr(address.length() - 30, 30).c_str());
    } else {
        addr = "Master Account - " + QString(address.c_str());
    }
    ui->reqAddress->addItem(addr);

    //Set lineEditAddress to Master Account address for copy to clipboard
    if (screenWidth <= 1024) {
        //(truncated for screen with less availableGeometry than 1024px)
        ui->lineEditAddress->setText(QString(address.substr(0, 30).c_str()) + "..." + QString(address.substr(address.length() - 30, 30).c_str()));
    } else {
        ui->lineEditAddress->setText(QString(address.c_str()));
    }

}

/*void ReceiveCoinsDialog::loadAccount() {
    QRect rec = QApplication::desktop()->availableGeometry();
    int screenWidth = rec.width();
    QString addr;

    //Set reqAddress as the master stealth address
    std::vector<std::string> addrList, accountList;
    CWallet* wl = model->getCWallet();
    QList<QString> stringsList;
    wl->AllMyPublicAddresses(addrList, accountList);
    for(size_t i = 0; i < addrList.size(); i++) {
        if (accountList[i] == "masteraccount") continue;
        bool isDuplicate = false;
            if (screenWidth <= 1280) {
                //(truncated for screen with less availableGeometry than 1280px)
                addr = QString(accountList[i].c_str()) + " - " + QString(addrList[i].substr(0, 30).c_str()) + "..." + QString(addrList[i].substr(addrList[i].length() - 30, 30).c_str());
            } else {
                addr = QString(accountList[i].c_str()) + " - " + QString(addrList[i].c_str());
            }
        for (size_t i = 0; i < (size_t)ui->reqAddress->count(); i++) {
            if (stringsList.contains(QString(addrList[i].substr(0, 30).c_str()) + "..." + QString(addrList[i].substr(addrList[i].length() - 30, 30).c_str()))) {
                isDuplicate = true;
                break;
            }
        }
        if (!isDuplicate) {
            stringsList.append(addr);
        }
    }
    ui->reqAddress->addItems(stringsList);
    //Set lineEditAddress to Master Account address for copy to clipboard
    if (screenWidth <= 1024) {
        //(truncated for screen with less availableGeometry than 1024px)
        ui->lineEditAddress->setText(QString(addrList[0].substr(0, 30).c_str()) + "..." + QString(addrList[0].substr(addrList[0].length() - 30, 30).c_str()));
    } else {
        ui->lineEditAddress->setText(QString(addrList[0].c_str()));
    }
}
*/

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    delete ui;
}

void ReceiveCoinsDialog::clear()
{
    updateDisplayUnit();
}

void ReceiveCoinsDialog::reject()
{
    clear();
}

void ReceiveCoinsDialog::accept()
{
    clear();
}

void ReceiveCoinsDialog::updateDisplayUnit()
{
}

void ReceiveCoinsDialog::on_receiveButton_clicked()
{
    double dAmount = ui->reqAmount->text().toDouble();
    CAmount maxMoneyInCoins = MAX_MONEY_OUT / COIN;
    CAmount maxMoneyInMillions = maxMoneyInCoins / 1000000;
    if (dAmount < 0.0 || dAmount > maxMoneyInCoins) {
        GUIUtil::showMessageBox(
            tr("Invalid Amount"),
            tr("Invalid amount entered. Please enter an amount less than %1 (%2M) PRCY.").arg(maxMoneyInCoins).arg(maxMoneyInMillions),
            QMessageBox::Warning);
        return;
    }
    if (!model || !model->getOptionsModel() || !model->getAddressTableModel())
        return;

    QString str = ui->reqAddress->currentText();
    QStringList list = str.split("-");

    QString address = list[1].trimmed();
    QString label = list[0].trimmed();
    QString reqMes = ui->reqID->text();

    SendCoinsRecipient info(address, label, getValidatedAmount(), reqMes);
    ReceiveRequestDialog* dialog = new ReceiveRequestDialog(this);
    dialog->setAttribute(Qt::WA_DeleteOnClose);
    dialog->setModel(model->getOptionsModel());
    dialog->setInfo(info);
    dialog->show();
    clear();
}

// We override the virtual resizeEvent of the QWidget to adjust tables column
// sizes as the tables width is proportional to the dialogs width.
void ReceiveCoinsDialog::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}

void ReceiveCoinsDialog::keyPressEvent(QKeyEvent* event)
{
    if (event->key() == Qt::Key_Return) {
        // press return -> submit form
        if (ui->reqAddress->hasFocus() || ui->reqAmount->hasFocus() || ui->reqID->hasFocus()) {
            event->ignore();
            on_receiveButton_clicked();
            return;
        }
    }

    this->QDialog::keyPressEvent(event);
}

void ReceiveCoinsDialog::copyAddress(){
    QClipboard *clipboard = QApplication::clipboard();
    if (ui->lineEditAddress->text().contains(".")) {
        // It's a smaller screen, don't copy the line text as it is truncated
        QString addr;
        std::string address;
        pwalletMain->ComputeStealthPublicAddress("masteraccount", address);
        clipboard->setText(QString(address.c_str()));
    } else {
        clipboard->setText(ui->lineEditAddress->text());
    }
}

void ReceiveCoinsDialog::generateAddress()
{
    uint64_t paymentID = 0;
    QClipboard *clipboard = QApplication::clipboard();
    QString addAccountString;
    std::string address;
    address = pwalletMain->GenerateIntegratedAddressWithRandomPaymentID("masteraccount", paymentID);

    bool ok;
    QString label = QInputDialog::getText(this, tr("Enter Label"),
                                          tr("Label (Payment ID is added by default)"), QLineEdit::Normal,
                                          QString::number(paymentID), &ok);

    if (ok && !label.isEmpty()) {
        if (label.contains(QString::number(paymentID))) {
            addAccountString = label.append(" - ").append(QString(address.c_str()));
        } else {
            addAccountString = label.append(" (").append(QString::number(paymentID)).append(") - ").append(QString(address.c_str()));
        }
    } else if (!ok) {
        return;
    }

    ui->reqAddress->addItem(addAccountString);
    ui->reqAddress->setCurrentIndex(ui->reqAddress->count() - 1);
    clipboard->setText(QString(address.c_str()));
}

void ReceiveCoinsDialog::removeAddress()
{
    if (ui->reqAddress->currentText().contains("Master Account")) return;
    ui->reqAddress->removeItem(ui->reqAddress->currentIndex());
}

void ReceiveCoinsDialog::changeAddress(int)
{
    QString str = ui->reqAddress->currentText();
    QStringList list = str.split("-");
    QString address = list[1].trimmed();
    //Set lineEditAddress to Currently Selected Account address for copy to clipboard
    ui->lineEditAddress->setText(address);
}
