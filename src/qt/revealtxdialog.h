#ifndef REVEALTXDIALOG_H
#define REVEALTXDIALOG_H

#include "amount.h"

#include <QCheckBox>
#include <QDialog>
#include <QSettings>

namespace Ui {
class RevealTxDialog;
}

class RevealTxDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RevealTxDialog(QWidget *parent = 0);
    ~RevealTxDialog();

    void setTxID(QString strId);
    void setTxAddress(QString strAddr);
    void setTxPrivKey(QString strPrivKey);
    void setTxAmount(QString amount);
    void setTxFee(CAmount fee);
    void setTxPaymentID(uint64_t paymentID);
    void setTxRingSize(int64_t ringSize);

private Q_SLOTS:
    void on_buttonBox_accepted();
    void copyID();
    void copyAddress();
    void copyPrivateKey();
    void copyTxAmount();
    void copyTxFee();
    void copyTxPaymentID();
    void copyTxRingSize();
    void openTXinExplorer();
    void deleteTransaction();

private:
    Ui::RevealTxDialog *ui;
    QSettings settings;

protected:
    void keyPressEvent(QKeyEvent* event);
};

#endif // REVEALTXDIALOG_H
