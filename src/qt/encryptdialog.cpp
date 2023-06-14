#include "encryptdialog.h"
#include "ui_encryptdialog.h"
#include "guiutil.h"
#include "guiconstants.h"
#include "bitcoingui.h"
#include "zxcvbn.h"

#include <QMessageBox>
#include <QCloseEvent>

EncryptDialog::EncryptDialog(QWidget *parent) :
    QDialog(parent, Qt::WindowSystemMenuHint | Qt::WindowTitleHint | Qt::WindowCloseButtonHint),
    ui(new Ui::EncryptDialog)
{
    ui->setupUi(this);

    connect(ui->linePwd, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPass()));
    connect(ui->linePwdConfirm, SIGNAL(textChanged(const QString &)), this, SLOT(validateNewPassRepeat()));
    connect(ui->btnOK, SIGNAL(clicked()), this, SLOT(on_acceptPassphrase()));
    connect(ui->btnCancel, SIGNAL(clicked()), this, SLOT(on_btnCancel()));
    connect(ui->showPassphraseCheckBox, SIGNAL(clicked()), this, SLOT(on_showPassphraseCheckBox_clicked()));
}

EncryptDialog::~EncryptDialog()
{
    delete ui;
}

void EncryptDialog::setModel(WalletModel* model)
{
    this->model = model;
}

void EncryptDialog::closeEvent (QCloseEvent *event)
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, tr("Wallet Encryption Required"), tr("There was no passphrase entered for the wallet.\n\nWallet encryption is required for the security of your funds.\n\nWhat would you like to do?"), QMessageBox::Retry|QMessageBox::Close);
      if (reply == QMessageBox::Retry) {
      event->ignore();
      } else {
      QApplication::quit();
      }
}

void EncryptDialog::on_btnCancel()
{
    QMessageBox::StandardButton reply;
    reply = QMessageBox::warning(this, tr("Wallet Encryption Required"), tr("There was no passphrase entered for the wallet.\n\nWallet encryption is required for the security of your funds.\n\nWhat would you like to do?"), QMessageBox::Retry|QMessageBox::Close);
      if (reply == QMessageBox::Retry) {
      return;
      } else {
      QApplication::quit();
      }
}

void EncryptDialog::on_acceptPassphrase() {
    SecureString newPass = SecureString();
    newPass.reserve(MAX_PASSPHRASE_SIZE);
    newPass.assign( ui->linePwd->text().toStdString().c_str() );

    SecureString newPass2 = SecureString();
    newPass2.reserve(MAX_PASSPHRASE_SIZE);
    newPass2.assign(ui->linePwdConfirm->text().toStdString().c_str() );

    if ( (!ui->linePwd->text().length()) || (!ui->linePwdConfirm->text().length()) ) {
      GUIUtil::showMessageBox(
          tr("Wallet Encryption Failed"),
          tr("The passphrase entered for wallet encryption was empty. Please try again."),
          QMessageBox::Critical);
      return;
    }
    
    if (newPass == newPass2) {
        if (newPass.length() < 10) {
            GUIUtil::showMessageBox(
                tr("Wallet Encryption Failed"),
                tr("The passphrase's length has to be more than 10. Please try again."),
                QMessageBox::Critical);
            return;
        }

        if (!pwalletMain->checkPassPhraseRule(newPass.c_str())) {
            GUIUtil::showMessageBox(
                tr("Wallet Encryption Failed"),
                tr("The passphrase must contain lower, upper, digit, symbol. Please try again."),
                QMessageBox::Critical);
            return;
        }

        double guesses;
        int ret = zxcvbn_password_strength(newPass.c_str(), NULL, &guesses, NULL);
        if (ret < 0 || guesses < 10000) {
            GUIUtil::showMessageBox(
                tr("Wallet Encryption Failed"),
                tr("The passphrases entered for wallet encryption is too weak. Please try again."),
                QMessageBox::Critical);
            return;
        }

        if (model->setWalletEncrypted(true, newPass)) {
            pwalletMain->nTimeFirstKey = 1;
            model->setWalletLocked(false, newPass);
            GUIUtil::showMessageBox(
                tr("Wallet Encryption Successful"),
                tr("Wallet passphrase was successfully set.\nPlease remember your passphrase as there is no way to recover it."),
                QMessageBox::Information);
            accept();
        }
    } else {
        GUIUtil::showMessageBox(
            tr("Wallet Encryption Failed"),
            tr("The passphrases entered for wallet encryption do not match. Please try again."),
            QMessageBox::Critical);
        return;
    }
}

void EncryptDialog::validateNewPass()
{
    if (!ui->linePwd->text().length())
        ui->linePwd->setStyleSheet("border-color: red");
    else ui->linePwd->setStyleSheet(GUIUtil::loadStyleSheet());
    matchNewPasswords();
    ui->linePwd->repaint();
}

void EncryptDialog::validateNewPassRepeat()
{
    matchNewPasswords();
}

bool EncryptDialog::matchNewPasswords()
{
    if (ui->linePwd->text()==ui->linePwdConfirm->text())
    {
        ui->linePwdConfirm->setStyleSheet(GUIUtil::loadStyleSheet());
        ui->linePwdConfirm->repaint();
        return true;
    } else
    {
        ui->linePwdConfirm->setStyleSheet("border-color: red");
        ui->linePwdConfirm->repaint();
        return false;
    }
}

void EncryptDialog::on_showPassphraseCheckBox_clicked()
{
    ui->linePwd->setEchoMode(ui->showPassphraseCheckBox->checkState() == Qt::Checked ? QLineEdit::Normal : QLineEdit::Password);
    ui->linePwdConfirm->setEchoMode(ui->showPassphraseCheckBox->checkState() == Qt::Checked ? QLineEdit::Normal : QLineEdit::Password);
}

