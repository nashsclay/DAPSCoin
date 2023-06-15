// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "optionspage.h"
#include "ui_optionspage.h"

#include "addressbookpage.h"
#include "addresstablemodel.h"
#include "bitcoinunits.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"
#include "masternode-sync.h"
#include "optionsmodel.h"
#include "receiverequestdialog.h"
#include "walletmodel.h"
#include "2faqrdialog.h"
#include "2fadialog.h"
#include "2faconfirmdialog.h"
#include "zxcvbn.h"
#include "utilmoneystr.h"
#include "timedata.h"

#include <QAction>
#include <QCursor>
#include <QItemSelection>
#include <QMessageBox>
#include <QScrollBar>
#include <QTextDocument>
#include <QDataWidgetMapper>
#include <QDoubleValidator>
#include <QFile>
#include <QTextStream>


OptionsPage::OptionsPage(QWidget* parent) : QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
                                                          ui(new Ui::OptionsPage),
                                                          model(0),
                                                          // m_SizeGrip(this),
                                                          mapper(0)
{
    ui->setupUi(this);

    mapper = new QDataWidgetMapper(this);
    mapper->setSubmitPolicy(QDataWidgetMapper::ManualSubmit);

    ui->toggleTheme->setState(settings.value("theme")!="webwallet");
    connect(ui->toggleTheme, SIGNAL(stateChanged(ToggleButton*)), this, SLOT(changeTheme(ToggleButton*)));

    connect(ui->lineEditNewPass, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPass()));
    connect(ui->lineEditNewPassRepeat, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPassRepeat()));
    connect(ui->lineEditOldPass, SIGNAL(textChanged(const QString &)), this, SLOT(onOldPassChanged()));

    QLocale lo(QLocale::C);
    lo.setNumberOptions(QLocale::RejectGroupSeparator);
    QDoubleValidator *dblVal = new QDoubleValidator(0, 250000000, 0, ui->lineEditWithhold);
    dblVal->setNotation(QDoubleValidator::StandardNotation);
    dblVal->setLocale(lo);
    ui->lineEditWithhold->setValidator(dblVal);
    ui->lineEditWithhold->setPlaceholderText("PRCY Amount");
    if (nReserveBalance > 0)
        ui->lineEditWithhold->setText(BitcoinUnits::format(0, nReserveBalance).toUtf8());

    bool stkStatus = pwalletMain->ReadStakingStatus();
    fLiteMode = GetBoolArg("-litemode", false);
    if (stkStatus && !fLiteMode){
        if (chainActive.Height() < Params().LAST_POW_BLOCK()) {
            stkStatus = false;
            pwalletMain->WriteStakingStatus(false);
            //Q_EMIT model->stakingStatusChanged(false);
        } else {
            QString error;
            StakingStatusError stt = model->getStakingStatusError(error);
            if (error.length()) {
                stkStatus = false;
                pwalletMain->WriteStakingStatus(false);
                //Q_EMIT model->stakingStatusChanged(false);
            }
        }
    }

    if (!fLiteMode) {
        //Staking related items and functions
        ui->toggleStaking->setState(nLastCoinStakeSearchInterval | stkStatus);
        connect(ui->toggleStaking, SIGNAL(stateChanged(ToggleButton*)), this, SLOT(on_EnableStaking(ToggleButton*)));
        timerStakingToggleSync = new QTimer();
        connect(timerStakingToggleSync, SIGNAL(timeout()), this, SLOT(setStakingToggle()));
        timerStakingToggleSync->start(10000);
        ui->labelStaking->show();
        ui->toggleStaking->show();
        ui->reservegroupBox->show();
        ui->lineEditWithhold->show();
        ui->addNewFunds->show();
        ui->pushButtonSave->show();
        ui->pushButtonDisable->show();
    } else {
        //Staking related items and functions hidden/removed in litemode
        ui->labelStaking->hide();
        ui->toggleStaking->hide();
        ui->reservegroupBox->hide();
        ui->lineEditWithhold->hide();
        ui->addNewFunds->hide();
        ui->pushButtonSave->hide();
        ui->pushButtonDisable->hide();
    }


    connect(ui->pushButtonRecovery, SIGNAL(clicked()), this, SLOT(onShowMnemonic()));

    bool twoFAStatus = pwalletMain->Read2FA();
    if (twoFAStatus)
        enable2FA();
    else
        disable2FA();

    ui->toggle2FA->setState(twoFAStatus);
    connect(ui->toggle2FA, SIGNAL(stateChanged(ToggleButton*)), this, SLOT(on_Enable2FA(ToggleButton*)));
    QSettings settings;
    int digits = settings.value("2fadigits").toInt();
    if (digits == 8) {
        ui->comboBox->setCurrentIndex(1);
    } else if (digits == 6) {
        ui->comboBox->setCurrentIndex(0);
    }
    connect(ui->comboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(changeDigits(int)));
    connect(ui->btn_day, SIGNAL(clicked()), this, SLOT(on_day()));
    connect(ui->btn_week, SIGNAL(clicked()), this, SLOT(on_week()));
    connect(ui->btn_month, SIGNAL(clicked()), this, SLOT(on_month()));

    ui->lblAuthCode->setVisible(false);
    ui->code_1->setVisible(false);
    ui->code_2->setVisible(false);
    ui->code_3->setVisible(false);
    ui->code_4->setVisible(false);
    ui->code_5->setVisible(false);
    ui->code_6->setVisible(false);

    if (!pwalletMain->IsMasternodeController()) {
        if (pwalletMain) {
            bool isConsolidatedOn = pwalletMain->IsAutoConsolidateOn();
            ui->addNewFunds->setChecked(isConsolidatedOn);
        }
    } else {
        ui->addNewFunds->setChecked(false);
        ui->addNewFunds->setEnabled(false);
        QFont font = ui->addNewFunds->font();
        font.setStrikeOut(true);
        ui->addNewFunds->setFont(font);
        ui->addNewFunds->setToolTip("Disabled by default due to controlling Masternode(s) from this wallet.\nEnabling this will incur a maximum 0.1 PRCY fee each time you receive a new deposit that needs to be consolidated for staking.");
    }
    ui->mapPortUpnp->setChecked(settings.value("fUseUPnP", false).toBool());
    ui->minimizeToTray->setChecked(settings.value("fMinimizeToTray", false).toBool());
    ui->minimizeOnClose->setChecked(settings.value("fMinimizeOnClose", false).toBool());
    ui->alwaysRequest2FA->setChecked(settings.value("fAlwaysRequest2FA", false).toBool());
    ui->alwaysRequestPassphrase->setChecked(settings.value("fAlwaysRequestPassphrase", false).toBool());
    ui->hideBalanceStaking->setChecked(settings.value("fHideBalance", false).toBool());
    ui->lockSendStaking->setChecked(settings.value("fLockSendStaking", false).toBool());
    ui->displayCurrencyValue->setChecked(settings.value("fDisplayCurrencyValue", false).toBool());
    ui->defaultCurrency->setCurrentText(settings.value("strDefaultCurrency").toString());
    connect(ui->addNewFunds, SIGNAL(stateChanged(int)), this, SLOT(setAutoConsolidate(int)));
    connect(ui->mapPortUpnp, SIGNAL(stateChanged(int)), this, SLOT(mapPortUpnp_clicked(int)));
    connect(ui->minimizeToTray, SIGNAL(stateChanged(int)), this, SLOT(minimizeToTray_clicked(int)));
    connect(ui->minimizeOnClose, SIGNAL(stateChanged(int)), this, SLOT(minimizeOnClose_clicked(int)));
    connect(ui->alwaysRequest2FA, SIGNAL(stateChanged(int)), this, SLOT(alwaysRequest2FA_clicked(int)));
    connect(ui->hideBalanceStaking, SIGNAL(stateChanged(int)), this, SLOT(hideBalanceStaking_clicked(int)));
    connect(ui->lockSendStaking, SIGNAL(stateChanged(int)), this, SLOT(lockSendStaking_clicked(int)));
    connect(ui->displayCurrencyValue, SIGNAL(stateChanged(int)), this, SLOT(displayCurrencyValue_clicked(int)));
    connect(ui->defaultCurrency, SIGNAL(currentIndexChanged(int)), this, SLOT(setDefaultCurrency(int)));
    connect(ui->showPassphraseCheckBox, SIGNAL(clicked()), this, SLOT(on_showPassphraseCheckBox_clicked()));
}

void OptionsPage::setStakingToggle()
{
    ui->toggleStaking->setState(fGeneratePrcycoins);
}

void OptionsPage::setModel(WalletModel* model)
{
    this->model = model;
    this->options = model->getOptionsModel();

    mapper->setModel(options);
    setMapper();
    mapper->toFirst();
}

static inline int64_t roundint64(double d)
{
    return (int64_t)(d > 0 ? d + 0.5 : d - 0.5);
}

CAmount OptionsPage::getValidatedAmount() {
    double dAmount = ui->lineEditWithhold->text().toDouble();
    CAmount nAmount = roundint64(dAmount * COIN);
    return nAmount;
}

OptionsPage::~OptionsPage()
{
    delete timerStakingToggleSync;
    delete ui;
}

void OptionsPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
}

void OptionsPage::on_pushButtonSave_clicked() {
    double dAmount = ui->lineEditWithhold->text().toDouble();
    if (ui->lineEditWithhold->text().trimmed().isEmpty()) {
        ui->lineEditWithhold->setStyleSheet("border: 2px solid red");
        GUIUtil::showMessageBox(
            tr("Reserve Balance Empty"),
            tr("PRCY reserve amount is empty and must be a minimum of 1.\nPlease click Disable if you would like to turn it off."),
            QMessageBox::Information);
        return;
    }
    if (dAmount < 0.0 || dAmount > MAX_MONEY_OUT) {
        CAmount maxMoneyInCoins = MAX_MONEY_OUT / COIN;
        CAmount maxMoneyInMillions = maxMoneyInCoins / 1000000;
        GUIUtil::showMessageBox(
            tr("Invalid Reserve Amount"),
            tr("The amount you have attempted to keep as spendable is greater than the %1 (%2M) limit. Please try a smaller amount.").arg(maxMoneyInCoins).arg(maxMoneyInMillions),
            QMessageBox::Warning);
        return;
    }
    nReserveBalance = getValidatedAmount();

    CWalletDB walletdb(pwalletMain->strWalletFile);
    walletdb.WriteReserveAmount(nReserveBalance / COIN);

    Q_EMIT model->stakingStatusChanged(nLastCoinStakeSearchInterval);
    ui->lineEditWithhold->setStyleSheet(GUIUtil::loadStyleSheet());

    QString reserveBalance = ui->lineEditWithhold->text().trimmed();
    GUIUtil::showMessageBox(
        tr("Reserve Balance Set"),
        tr("Reserve balance of %1 PRCY is successfully set.").arg(reserveBalance),
        QMessageBox::Information);
}

void OptionsPage::on_pushButtonDisable_clicked() {
    ui->lineEditWithhold->setText("0");

    CWalletDB walletdb(pwalletMain->strWalletFile);
    walletdb.WriteReserveAmount(0);

    Q_EMIT model->stakingStatusChanged(nLastCoinStakeSearchInterval);
    GUIUtil::showMessageBox(
        tr("Reserve Balance Disabled"),
        tr("Reserve balance disabled."),
        QMessageBox::Information);
}

void OptionsPage::keyPressEvent(QKeyEvent* event)
{

    this->QDialog::keyPressEvent(event);
}

void OptionsPage::setMapper()
{
}

void OptionsPage::on_pushButtonPassword_clicked()
{
    if ( (!ui->lineEditNewPass->text().length()) || (!ui->lineEditNewPassRepeat->text().length()) ) {
        GUIUtil::showMessageBox(
            tr("Wallet Encryption Failed"),
            tr("The passphrase entered for wallet encryption was empty or contained spaces. Please try again."),
            QMessageBox::Critical);
        return;
    }
    //disable password submit button
    SecureString oldPass = SecureString();
    oldPass.reserve(MAX_PASSPHRASE_SIZE);
    oldPass.assign( ui->lineEditOldPass->text().toStdString().c_str() );
    SecureString newPass = SecureString();
    newPass.reserve(MAX_PASSPHRASE_SIZE);
    newPass.assign( ui->lineEditNewPass->text().toStdString().c_str() );

    SecureString newPass2 = SecureString();
    newPass2.reserve(MAX_PASSPHRASE_SIZE);
    newPass2.assign(ui->lineEditNewPassRepeat->text().toStdString().c_str() );

    bool success = false;

    if (newPass == newPass2) {
        double guesses;

        if (oldPass == newPass) {
            GUIUtil::showMessageBox(
                tr("Wallet Encryption Failed"),
                tr("The passphrase you have entered is the same as your old passphrase. Please use a different passphrase if you would like to change it."),
                QMessageBox::Critical);
        }
        else if (newPass.length() < 10) {
            GUIUtil::showMessageBox(
                tr("Wallet Encryption Failed"),
                tr("The passphrase's length has to be more than 10. Please try again."),
                QMessageBox::Critical);
        }
        else if (!pwalletMain->checkPassPhraseRule(newPass.c_str())) {
            GUIUtil::showMessageBox(
                tr("Wallet Encryption Failed"),
                tr("The passphrase must contain lower, upper, digit, symbol. Please try again."),
                QMessageBox::Critical);
        }
        else if (zxcvbn_password_strength(newPass.c_str(), NULL, &guesses, NULL) < 0 || guesses < 10000) {
            GUIUtil::showMessageBox(
                tr("Wallet Encryption Failed"),
                tr("The passphrase is too weak. You must use a minimum passphrase length of 10 characters and use uppercase letters, lowercase letters, numbers, and symbols. Please try again."),
                QMessageBox::Critical);
        }
        else if (model->changePassphrase(oldPass, newPass)) {
            GUIUtil::showMessageBox(
                tr("Passphrase Change Successful"),
                tr("Wallet passphrase was successfully changed.\nPlease remember your passphrase as there is no way to recover it."),
                QMessageBox::Information);
            success = true;
        }
    } else {
        GUIUtil::showMessageBox(
            tr("Wallet Encryption Failed"),
            tr("The passphrases entered for wallet encryption do not match. Please try again."),
            QMessageBox::Critical);
    }

    if (success)
        ui->pushButtonPassword->setStyleSheet("border: 2px solid green");
    else ui->pushButtonPassword->setStyleSheet("border: 2px solid red");
    ui->pushButtonPassword->repaint();
}

void OptionsPage::on_pushButtonPasswordClear_clicked()
{
    ui->lineEditOldPass->clear();
    ui->lineEditNewPass->clear();
    ui->lineEditNewPassRepeat->clear();
    ui->lineEditOldPass->setStyleSheet(GUIUtil::loadStyleSheet());
    ui->lineEditNewPass->setStyleSheet(GUIUtil::loadStyleSheet());
    ui->lineEditNewPassRepeat->setStyleSheet(GUIUtil::loadStyleSheet());
}

void OptionsPage::on_pushButtonBackup_clicked(){
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        tr("Wallet Data (*.dat)"), NULL);

    if (filename.isEmpty())
        return;

    if (model->backupWallet(QString(filename))) {
        ui->pushButtonBackup->setStyleSheet("border: 2px solid green");
        QString msg = tr("Wallet has been successfully backed up to ");
        GUIUtil::showMessageBox(
            tr("Wallet Backup Successful"),
            msg + filename,
            QMessageBox::Information);
    } else {
        ui->pushButtonBackup->setStyleSheet("border: 2px solid red");
        GUIUtil::showMessageBox(
            tr("Wallet Backup Failed"),
            tr("Wallet backup failed. Please try again."),
            QMessageBox::Critical);
}
    ui->pushButtonBackup->repaint();
}

void OptionsPage::validateNewPass()
{
    if (!ui->lineEditNewPass->text().length())
        ui->lineEditNewPass->setStyleSheet("border-color: red");
    else ui->lineEditNewPass->setStyleSheet(GUIUtil::loadStyleSheet());
    matchNewPasswords();
    ui->lineEditNewPass->repaint();
}

void OptionsPage::validateNewPassRepeat()
{
    matchNewPasswords();
}

void OptionsPage::onOldPassChanged()
{
    QString stylesheet = GUIUtil::loadStyleSheet();
    ui->lineEditOldPass->setStyleSheet(stylesheet);
    ui->lineEditOldPass->repaint();
    ui->pushButtonPassword->setStyleSheet(stylesheet);
    ui->pushButtonPassword->repaint();
    if (!ui->lineEditNewPass->text().length())
        ui->lineEditNewPass->setStyleSheet("border-color: red");
    ui->lineEditNewPass->repaint();
}

bool OptionsPage::matchNewPasswords()
{
    if (ui->lineEditNewPass->text()==ui->lineEditNewPassRepeat->text())
    {
        ui->lineEditNewPassRepeat->setStyleSheet(GUIUtil::loadStyleSheet());
        ui->lineEditNewPassRepeat->repaint();
        return true;
    } else
    {
        ui->lineEditNewPassRepeat->setStyleSheet("border-color: red");
        ui->lineEditNewPassRepeat->repaint();
        return false;
    }
}

void OptionsPage::on_EnableStaking(ToggleButton* widget)
{
    if (!masternodeSync.IsSynced()) {
        GUIUtil::showMessageBox(
            tr("Staking Disabled - Syncing Masternode list"),
            tr("Enable Staking is disabled when you are still syncing the Masternode list as this is required. Please allow the wallet to fully sync this list before attempting to Enable Staking."),
            QMessageBox::Warning);
        return;
    }
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForStakingOnly) {
        GUIUtil::showMessageBox(
            tr("Staking Setting"),
            tr("Please unlock the wallet with your passphrase before changing this setting."),
            QMessageBox::Information);
        widget->setState(!widget->getState());
        return;
    }

    QString errorMessage;
    if (chainActive.Height() < Params().LAST_POW_BLOCK()) {
        if (widget->getState()) {
            int lastPowBlock = Params().LAST_POW_BLOCK();
            errorMessage = tr("PoW blocks are still being mined.\nPlease wait until Block %1.").arg(lastPowBlock);
            GUIUtil::showMessageBox(
                tr("Information"),
                errorMessage,
                QMessageBox::Information);
        }
        widget->setState(false);
        pwalletMain->WriteStakingStatus(false);
        return;
    }
    if (widget->getState()){
        CAmount minFee, maxFee;
        const CAmount minStakingAmount = model->getMinStakingAmount();
        StakingStatusError stt = pwalletMain->StakingCoinStatus(minFee, maxFee);
        if (stt == StakingStatusError::UNSTAKABLE_BALANCE_TOO_LOW ||
            stt == UNSTAKABLE_BALANCE_RESERVE_TOO_HIGH ||
            stt == UNSTAKABLE_BALANCE_RESERVE_TOO_HIGH_CONSOLIDATION_FAILED ||
            stt == UNSTAKABLE_BALANCE_TOO_LOW_CONSOLIDATION_FAILED) {

            if (stt == StakingStatusError::UNSTAKABLE_BALANCE_TOO_LOW) {
                errorMessage = tr("Your stakeable balance is under the threshold of %1 PRCY. Please deposit more PRCY into your account in order to enable staking.").arg(minStakingAmount);
            } else if (stt == UNSTAKABLE_BALANCE_TOO_LOW_CONSOLIDATION_FAILED) {
                errorMessage = tr("Your balance requires a consolidation transaction which incurs a fee of between %1 to %2 PRCY. However after that transaction fee, your balance will be below the staking threshold of %3 PRCY. Please deposit more PRCY into your account or reduce your reserved amount in order to enable staking.")
                          .arg(QString::fromStdString(FormatMoney(minFee)))
                          .arg(QString::fromStdString(FormatMoney(maxFee)))
                          .arg(minStakingAmount);
            } else if (stt == UNSTAKABLE_BALANCE_RESERVE_TOO_HIGH) {
                errorMessage = tr("Your stakeable balance is under the threshold of %1 PRCY. This is due to your reserve balance being too high. Please deposit more PRCY into your account or reduce your reserved amount in order to enable staking.").arg(minStakingAmount);
            } else {
                SetRingSize(0);
                CAmount totalFee = maxFee + pwalletMain->ComputeFee(1, 2, MAX_RING_SIZE);
                errorMessage = tr("Your stakeable balance is under the threshold of %1 PRCY. This is due to your reserve balance of %2 PRCY being too high. The wallet software has tried to consolidate your funds with the reserve balance but without success because of a consolidation fee of %3 PRCY. Please wait around 10 minutes for the wallet to resolve the reserve to enable staking.")
                          .arg(minStakingAmount)
                          .arg(QString::fromStdString(FormatMoney(nReserveBalance)))
                          .arg(QString::fromStdString(FormatMoney(totalFee)));
            }
            GUIUtil::showMessageBox(
                tr("Warning: Staking Issue"),
                errorMessage,
                QMessageBox::Warning);
            widget->setState(false);
            nLastCoinStakeSearchInterval = 0;
            Q_EMIT model->stakingStatusChanged(false);
            pwalletMain->WriteStakingStatus(false);
            return;
        }
        if (stt == StakingStatusError::STAKING_OK) {
            pwalletMain->WriteStakingStatus(true);
            Q_EMIT model->stakingStatusChanged(true);
            model->generateCoins(true, 1);
            pwalletMain->fCombineDust = true;
            pwalletMain->combineMode = CombineMode::ON;
            saveConsolidationSettingTime(ui->addNewFunds->isChecked());
            return;
        }

        if (stt == StakingStatusError::STAKABLE_NEED_CONSOLIDATION) {
            errorMessage = tr("In order to enable staking with 100%% of your current balance, your previous PRCY deposits must be consolidated and reorganized. This will incur a fee of between %1 to %2 PRCY.\n\nWould you like to do this?")
                           .arg(QString::fromStdString(FormatMoney(minFee)))
                           .arg(QString::fromStdString(FormatMoney(maxFee)));
        } else {
            errorMessage = tr("In order to enable staking with 100%% of your current balance except the reserve balance, your previous PRCY deposits must be consolidated and reorganized. This will incur a fee of between %1 to %2 PRCY.\n\nWould you like to do this?")
                           .arg(QString::fromStdString(FormatMoney(minFee)))
                           .arg(QString::fromStdString(FormatMoney(maxFee)));
        }
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, tr("Staking Needs Consolidation"), errorMessage, QMessageBox::Yes|QMessageBox::No|QMessageBox::Ignore);
        if (reply == QMessageBox::Yes) {
            pwalletMain->WriteStakingStatus(true);
            Q_EMIT model->stakingStatusChanged(true);
            model->generateCoins(true, 1);
            pwalletMain->fCombineDust = true;
            pwalletMain->combineMode = CombineMode::ON;
            saveConsolidationSettingTime(ui->addNewFunds->isChecked());
            bool success = false;
            try {
                uint32_t nTime = pwalletMain->ReadAutoConsolidateSettingTime();
                nTime = (nTime == 0)? GetAdjustedTime() : nTime;
                success = model->getCWallet()->CreateSweepingTransaction(
                                minStakingAmount,
                                minStakingAmount, nTime);
                if (success) {
                    //nConsolidationTime = 1800;
                    GUIUtil::showMessageBox(
                        tr("Information"),
                        tr("Consolidation transaction created!"),
                        QMessageBox::Information);
                }
            } catch (const std::exception& err) {
                LogPrintf("Sweeping failed, will be done automatically when coins become mature");
            }
            return;
        } else if (reply == QMessageBox::No) {
            nLastCoinStakeSearchInterval = 0;
            model->generateCoins(false, 0);
            Q_EMIT model->stakingStatusChanged(false);
            pwalletMain->WriteStakingStatus(false);
            return;
        } else {
            pwalletMain->WriteStakingStatus(true);
            Q_EMIT model->stakingStatusChanged(true);
            model->generateCoins(true, 1);
            return;
        }
        /* if (!error.length()) {
            pwalletMain->WriteStakingStatus(true);
            Q_EMIT model->stakingStatusChanged(true);
            model->generateCoins(true, 1);
        } else {
            if (stt != StakingStatusError::UTXO_UNDER_THRESHOLD) {
                QMessageBox msgBox;
                QString msg(error);
                msgBox.setWindowTitle("Warning: Staking Issue");
                msgBox.setIcon(QMessageBox::Warning);
                msgBox.setText(msg);
                msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                msgBox.exec();
                widget->setState(false);
                nLastCoinStakeSearchInterval = 0;
                Q_EMIT model->stakingStatusChanged(false);
                pwalletMain->WriteStakingStatus(false);
            } else {
                QMessageBox::StandardButton reply;
                reply = QMessageBox::question(this, "Create Stakable Transaction?", error, QMessageBox::Yes|QMessageBox::No);
                if (reply == QMessageBox::Yes) {
                    //ask yes or no
                    //send to this self wallet MIN staking amount
                    std::string masterAddr;
                    model->getCWallet()->ComputeStealthPublicAddress("masteraccount", masterAddr);
                    CWalletTx resultTx;
                    bool success = false;
                    try {
                        success = model->getCWallet()->SendToStealthAddress(
                                masterAddr,
                                minStakingAmount,
                                resultTx,
                                false
                        );
                    } catch (const std::exception& err)
                    {
                        QMessageBox msgBox;
                        msgBox.setWindowTitle("Could Not Send");
                        msgBox.setIcon(QMessageBox::Warning);
                        msgBox.setText(QString(err.what()));
                        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                        msgBox.exec();
                        return;
                    }
                    if (success){
                        WalletUtil::getTx(pwalletMain, resultTx.GetHash());
                        QString txhash = resultTx.GetHash().GetHex().c_str();
                        QMessageBox msgBox;
                        QPushButton *copyButton = msgBox.addButton(tr("Copy"), QMessageBox::ActionRole);
                        copyButton->setStyleSheet("background:transparent;");
                        copyButton->setIcon(QIcon(":/icons/editcopy"));
                        msgBox.setWindowTitle("Transaction Initialized");
                        msgBox.setText("Transaction initialized.\n\n" + txhash);
                        msgBox.setStyleSheet(GUIUtil::loadStyleSheet());
                        msgBox.setIcon(QMessageBox::Information);
                        msgBox.exec();
                        if (msgBox.clickedButton() == copyButton) {
                        //Copy txhash to clipboard
                        GUIUtil::setClipboard(txhash);
                        }
                    }
                } else {
                    widget->setState(false);
                    nLastCoinStakeSearchInterval = 0;
                    Q_EMIT model->stakingStatusChanged(false);
                    pwalletMain->WriteStakingStatus(false);
                }
            }
        }*/
    } else {
        nLastCoinStakeSearchInterval = 0;
        model->generateCoins(false, 0);
        Q_EMIT model->stakingStatusChanged(false);
        pwalletMain->WriteStakingStatus(false);
    }
}

void OptionsPage::on_Enable2FA(ToggleButton* widget)
{
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForStakingOnly) {
        GUIUtil::showMessageBox(
            tr("2FA Setting"),
            tr("Please unlock the wallet with your passphrase before changing this setting."),
            QMessageBox::Information);

        ui->toggle2FA->setState(!ui->toggle2FA->getState());
        return;
    }

    if (widget->getState()) {
        TwoFAQRDialog qrdlg;
        qrdlg.setWindowTitle("2FA QR Code & Recovery Key");
        qrdlg.setModel(this->model);
        qrdlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&qrdlg, SIGNAL(finished (int)), this, SLOT(qrDialogIsFinished(int)));
        qrdlg.exec();
    } else {
        typeOf2FA = DISABLE;

        TwoFADialog codedlg;
        codedlg.setWindowTitle("2FA Code Verification");
        codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
        codedlg.exec();
    }
}

void OptionsPage::qrDialogIsFinished(int result) {
    if(result == QDialog::Accepted){
        TwoFADialog codedlg;
        codedlg.setWindowTitle("2FA Code Verification");
        codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
        connect(&codedlg, SIGNAL(finished (int)), this, SLOT(dialogIsFinished(int)));
        codedlg.exec();
    }

    if (result == QDialog::Rejected)
        ui->toggle2FA->setState(false);

}

void OptionsPage::dialogIsFinished(int result) {
   if(result == QDialog::Accepted){
        pwalletMain->Write2FA(true);
        QDateTime current = QDateTime::currentDateTime();
        pwalletMain->Write2FALastTime(current.toTime_t());
        enable2FA();

        GUIUtil::showMessageBox(
            tr("SUCCESS!"),
            tr("Two-factor authentication has been successfully enabled."),
            QMessageBox::Information);
   }

   if (result == QDialog::Rejected)
        ui->toggle2FA->setState(false);
}

void OptionsPage::changeTheme(ToggleButton* widget)
{
    if (widget->getState())
        settings.setValue("theme", "dark");
    else settings.setValue("theme", "webwallet");
        GUIUtil::refreshStyleSheet();
}

void OptionsPage::disable2FA() {
    ui->code_1->setText("");
    ui->code_2->setText("");
    ui->code_3->setText("");
    ui->code_4->setText("");
    ui->code_5->setText("");
    ui->code_6->setText("");

    ui->label_3->setEnabled(false);
    ui->lblAuthCode->setEnabled(false);
    ui->btn_day->setEnabled(false);
    ui->btn_week->setEnabled(false);
    ui->btn_month->setEnabled(false);

    ui->btn_day->setStyleSheet("border-color: none;");
    ui->btn_week->setStyleSheet("border-color: none;");
    ui->btn_month->setStyleSheet("border-color: none;");
    typeOf2FA = NONE2FA;
}

void OptionsPage::enable2FA() {
    ui->label_3->setEnabled(true);
    ui->lblAuthCode->setEnabled(true);
    ui->btn_day->setEnabled(true);
    ui->btn_week->setEnabled(true);
    ui->btn_month->setEnabled(true);

    QString code = QString::fromStdString(pwalletMain->Read2FASecret());
    if (code != "") {
        char chrlist[6];
        memcpy(chrlist, code.toUtf8().data(), 6);
        QString value;
        value.sprintf("%c", chrlist[0]);
        ui->code_1->setText(value);
        value.sprintf("%c", chrlist[1]);
        ui->code_2->setText(value);
        value.sprintf("%c", chrlist[2]);
        ui->code_3->setText(value);
        value.sprintf("%c", chrlist[3]);
        ui->code_4->setText(value);
        value.sprintf("%c", chrlist[4]);
        ui->code_5->setText(value);
        value.sprintf("%c", chrlist[5]);
        ui->code_6->setText(value);
    }

    int period = pwalletMain->Read2FAPeriod();
    typeOf2FA = NONE2FA;
    if (period == 1) {
        ui->btn_day->setStyleSheet("border-color: green;");
        typeOf2FA = DAY;
    }
    else if (period == 7) {
        ui->btn_week->setStyleSheet("border-color: green;");
        typeOf2FA = WEEK;
    }
    else if (period == 30) {
        ui->btn_month->setStyleSheet("border-color: green;");
        typeOf2FA = MONTH;
    }
}

void OptionsPage::confirmDialogIsFinished(int result) {
    if(result == QDialog::Accepted){
        if (typeOf2FA == DAY) {
            pwalletMain->Write2FAPeriod(1);
            ui->btn_day->setStyleSheet("border-color: green;");
            ui->btn_week->setStyleSheet("border-color: white;");
            ui->btn_month->setStyleSheet("border-color: white;");
        } else if (typeOf2FA == WEEK) {
            pwalletMain->Write2FAPeriod(7);
            ui->btn_day->setStyleSheet("border-color: white;");
            ui->btn_week->setStyleSheet("border-color: green;");
            ui->btn_month->setStyleSheet("border-color: white;");
        } else if (typeOf2FA == MONTH) {
            pwalletMain->Write2FAPeriod(30);
            ui->btn_day->setStyleSheet("border-color: white;");
            ui->btn_week->setStyleSheet("border-color: white;");
            ui->btn_month->setStyleSheet("border-color: green;");
        } else if (typeOf2FA == DISABLE) {
            pwalletMain->Write2FA(false);
            pwalletMain->Write2FASecret("");
            pwalletMain->Write2FAPeriod(0);
            pwalletMain->Write2FALastTime(0);
            disable2FA();
        }
    }

    if (result == QDialog::Rejected)
        ui->toggle2FA->setState(true);
}

void OptionsPage::on_day() {
    typeOf2FA = DAY;

    TwoFADialog codedlg;
    codedlg.setWindowTitle("2FA Code Verification");
    codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
    connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
    codedlg.exec();
}

void OptionsPage::on_week() {
    typeOf2FA = WEEK;

    TwoFADialog codedlg;
    codedlg.setWindowTitle("2FA Code Verification");
    codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
    connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
    codedlg.exec();
}

void OptionsPage::on_month() {
    typeOf2FA = MONTH;

    TwoFADialog codedlg;
    codedlg.setWindowTitle("2FA Code Verification");
    codedlg.setStyleSheet(GUIUtil::loadStyleSheet());
    connect(&codedlg, SIGNAL(finished (int)), this, SLOT(confirmDialogIsFinished(int)));
    codedlg.exec();
}

void OptionsPage::onShowMnemonic() {
    if(!model)
        return;

    model->showSeedPhrase();
}

void OptionsPage::setAutoConsolidate(int state) {
    checkForUnlock();
    LOCK(pwalletMain->cs_wallet);
    saveConsolidationSettingTime(ui->addNewFunds->isChecked());
}

void OptionsPage::saveConsolidationSettingTime(bool autoConsolidate)
{
    if (!pwalletMain->IsMasternodeController() && autoConsolidate) {
        pwalletMain->WriteAutoConsolidateSettingTime(0);
    } else {
        pwalletMain->WriteAutoConsolidateSettingTime(GetAdjustedTime());
    }
}

void OptionsPage::mapPortUpnp_clicked(int state)
{
    if (ui->mapPortUpnp->isChecked()) {
        settings.setValue("fUseUPnP", true);
    } else {
        settings.setValue("fUseUPnP", false);
    }
    GUIUtil::showMessageBox(
        tr("UPNP Settings"),
        tr("UPNP Settings successfully changed. Please restart the wallet for changes to take effect."),
        QMessageBox::Information);
}

void OptionsPage::minimizeToTray_clicked(int state)
{
    if (ui->minimizeToTray->isChecked()) {
        settings.setValue("fMinimizeToTray", true);
    } else {
        settings.setValue("fMinimizeToTray", false);
    }
}

void OptionsPage::minimizeOnClose_clicked(int state)
{
    if (ui->minimizeOnClose->isChecked()) {
        settings.setValue("fMinimizeOnClose", true);
    } else {
        settings.setValue("fMinimizeOnClose", false);
    }
}

void OptionsPage::changeDigits(int digit)
{
    checkForUnlock();
    bool twofastatus = pwalletMain->Read2FA();
    if (twofastatus) {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "Are You Sure?", "2FA is currently activated. Are you sure you would like to change the number of digits anyway?\nThis is not recommended unless you know what you are doing.", QMessageBox::Yes|QMessageBox::No);
        if (reply == QMessageBox::Yes) {
            digit = ui->comboBox->currentText().toInt();
            settings.setValue("2fadigits", digit);
            GUIUtil::showMessageBox(
                tr("2FA Digit Settings"),
                tr("2FA Digit Settings have been changed successfully."),
                QMessageBox::Information);
            return;
        } else {
            GUIUtil::showMessageBox(
                tr("2FA Digit Settings"),
                tr("2FA Digit Settings have not been changed."),
                QMessageBox::Information);
            return;
        }
    }
    digit = ui->comboBox->currentText().toInt();
    settings.setValue("2fadigits", digit);
}


void OptionsPage::alwaysRequest2FA_clicked(int state)
{
    checkForUnlock();
    bool twofastatus = pwalletMain->Read2FA();
    if (twofastatus && ui->alwaysRequest2FA->isChecked()) {
        settings.setValue("fAlwaysRequest2FA", true);
    } else {
        settings.setValue("fAlwaysRequest2FA", false);
    }
}

void OptionsPage::alwaysRequestPassphrase_clicked(int state)
{
    checkForUnlock();
    if (ui->alwaysRequestPassphrase->isChecked()) {
        settings.setValue("fAlwaysRequestPassphrase", true);
    } else {
        settings.setValue("fAlwaysRequestPassphrase", false);
    }
}

void OptionsPage::hideBalanceStaking_clicked(int state) {
    checkForUnlock();
    if (ui->hideBalanceStaking->isChecked()) {
        settings.setValue("fHideBalance", true);
    } else {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "Are You Sure?", "Are you sure you would like to disable your 'Hide Balance when unlocked'?\nYou will be required to enter your passphrase. Failed or canceled attempts will be logged.", QMessageBox::Yes|QMessageBox::No);
        if (reply == QMessageBox::Yes) {
            model->setWalletLocked(true);
            WalletModel::UnlockContext ctx(model->requestUnlock(AskPassphraseDialog::Context::Unlock_Full, true));
            if (!ctx.isValid()) {
                GUIUtil::showMessageBox(
                    tr("Hide Balance When Unlocked"),
                    tr("Attempt to Disable 'Hide Balance when unlocked' failed or canceled. Wallet Locked for security."),
                    QMessageBox::Information);
                LogPrintf("Attempt to Disable 'Hide Balance when unlocked' failed or canceled. Wallet Locked for security.\n");
                settings.setValue("fHideBalance", true);
                ui->hideBalanceStaking->setChecked(true);
                return;
            } else {
                SecureString pass;
                model->setWalletLocked(false, pass);
                settings.setValue("fHideBalance", false);
                LogPrintf("Disable 'Hide Balance when unlocked' successful.\n");
            }
        } else {
            LogPrintf("Attempt to Disable 'Hide Balance when unlocked' canceled.\n");
            settings.setValue("fHideBalance", true);
            ui->hideBalanceStaking->setChecked(true);
            return;
        }
    }
}

void OptionsPage::lockSendStaking_clicked(int state) {
    checkForUnlock();
    if (ui->lockSendStaking->isChecked()) {
        settings.setValue("fLockSendStaking", true);
    } else {
        QMessageBox::StandardButton reply;
        reply = QMessageBox::question(this, "Are You Sure?", "Are you sure you would like to disable your Lock Send Tab when unlocked?\nYou will be required to enter your passphrase. Failed or canceled attempts will be logged.", QMessageBox::Yes|QMessageBox::No);
        if (reply == QMessageBox::Yes) {
            model->setWalletLocked(true);
            WalletModel::UnlockContext ctx(model->requestUnlock(AskPassphraseDialog::Context::Unlock_Full, true));
            if (!ctx.isValid()) {
                GUIUtil::showMessageBox(
                    tr("Lock Send Tab When Unlocked"),
                    tr("Attempt to Disable 'Lock Send Tab when unlocked' failed or canceled. Wallet Locked for security."),
                    QMessageBox::Information);
                LogPrintf("Attempt to Disable 'Lock Send Tab when unlocked' failed or canceled. Wallet Locked for security.\n");
                settings.setValue("fLockSendStaking", true);
                ui->lockSendStaking->setChecked(true);
                return;
            } else {
                SecureString pass;
                model->setWalletLocked(false, pass);
                settings.setValue("fLockSendStaking", false);
                LogPrintf("Disable 'Lock Send Tab when unlocked' successful.\n");
            }
        } else {
            LogPrintf("Attempt to Disable 'Lock Send Tab when unlocked' canceled.\n");
            settings.setValue("fLockSendStaking", true);
            ui->lockSendStaking->setChecked(true);
            return;
        }
    }
}


void OptionsPage::displayCurrencyValue_clicked(int)
{
    checkForUnlock();
    if (ui->displayCurrencyValue->isChecked()) {
        settings.setValue("fDisplayCurrencyValue", true);
        // Only set default USD if one doesn't already exist
        if (!settings.contains("strDefaultCurrency"))
            settings.setValue("strDefaultCurrency", "USD");
    } else {
        settings.setValue("fDisplayCurrencyValue", false);
    }
}

void OptionsPage::setDefaultCurrency(int)
{
    checkForUnlock();
    settings.setValue("strDefaultCurrency", ui->defaultCurrency->currentText());
}

void OptionsPage::checkForUnlock()
{
    int status = model->getEncryptionStatus();
    if (status == WalletModel::Locked || status == WalletModel::UnlockedForStakingOnly) {
        GUIUtil::showMessageBox(
            tr("Password Locked Setting"),
            tr("Please unlock the wallet with your passphrase before changing this setting."),
            QMessageBox::Information);
        return;
    }
}

void OptionsPage::on_showPassphraseCheckBox_clicked()
{
    ui->lineEditOldPass->setEchoMode(ui->showPassphraseCheckBox->checkState() == Qt::Checked ? QLineEdit::Normal : QLineEdit::Password);
    ui->lineEditNewPass->setEchoMode(ui->showPassphraseCheckBox->checkState() == Qt::Checked ? QLineEdit::Normal : QLineEdit::Password);
    ui->lineEditNewPassRepeat->setEchoMode(ui->showPassphraseCheckBox->checkState() == Qt::Checked ? QLineEdit::Normal : QLineEdit::Password);
}
