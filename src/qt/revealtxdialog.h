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

    void setupButtons();
    void setTxID(QString strId);
    void setTxAddress(QString strAddr);
    void setTxPrivKey(QString strPrivKey);
    void setTxAmount(CAmount amount);
    void setTxFee(CAmount fee);
    void setTxPaymentID(uint64_t paymentID);
    void setTxRingSize(int64_t ringSize);
    void setBlockHeight(int blockheight);
    void setBlockHash(QString blockHash);

private Q_SLOTS:
    void on_buttonBox_accepted();
    void copyID();
    void copyAddress();
    void copyPrivateKey();
    void copyTxAmount();
    void copyTxFee();
    void copyTxPaymentID();
    void copyTxRingSize();
    void copyBlockHash();
    void copyBlockHeight();
    void openTXinExplorer();
    void openBlockInExplorer();
    void deleteTransaction();

private:
    Ui::RevealTxDialog *ui;
    QSettings settings;

protected:
    void keyPressEvent(QKeyEvent* event);
};

#endif // REVEALTXDIALOG_H
